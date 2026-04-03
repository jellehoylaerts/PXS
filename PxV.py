#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ACI PxV - Single-file full rewrite (optimized)
----------------------------------------------
- Fixes APIC pagination issues on large fabrics by using DN-list → subtree fetches.
- Collects fvRsPathAtt once (class-level) and filters locally for speed.
- Uses separate thread pools for class scans and subtree fetches.
- Preserves original CLI interface and output format.
- BD L2/L3 classification for PxV weight:
    * L2 BD (weight=1): unicastRoute=disabled AND no subnets configured.
    * L3 BD (weight=2): everything else (routing enabled, subnets present,
      or unicastRoute unset/unknown).
    * Flood-mode attributes (unkMacUcastAct, arpFlood, multiDstPktAct) do
      NOT affect the PxV weight — they describe flood behaviour only.

FIXES (April 2026):
- Fix #1:  collect_static_from_epgs: only process direct fvRsPathAtt children,
           avoid deep-walk re-processing in fallback path.
- Fix #2:  aaep_vlans: deduplicate infraRsFuncToEpg processing paths.
- Fix #3:  vlan_to_bd: guard against missing tDn in infraRsFuncToEpg.
- Fix #4:  compute_pxv_per_port: warn when "?" (unmapped) node entries are dropped.
- Fix #5:  bd_l3_map default=True (L3) warns when a BD DN is missing from the map.
- Fix #6:  fetch_subtrees: chunked to avoid APIC connection exhaustion.
- Fix #7:  EPG fetch uses targeted subtree classes only (no oversized payloads).
           (unchanged from original — already targeted; noted in comments)
- Fix #8:  flat_classes fetched in parallel via ThreadPoolExecutor.
- Fix #9:  RE_PHYS broadened to match any interface name inside phys-[...].
- Fix #10: expand_port_blk emits debug warning on missing/malformed fields.
- Fix #11: AAA login domain is configurable via --domain (no longer hardcoded).
- Fix #12: Removed redundant L() wrapping where input is already a list.
- Fix #13: Raw DNs stored separately; norm_dn used only for keying/comparison.

Author: (rewritten for performance, legacy detection refined; all review fixes applied)
"""

import os
import sys
import re
import json
import time
import argparse
import getpass
import urllib3
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- env ----------
APIC_ENV = {
    "LAB11":    "https://tfac02lab11.infra.lab.corp",
    "LAB21":    "https://tfac02lab21.infra.lab.corp",
    "LAB22":    "https://tfac02lab22.infra.lab.corp",
    "LAB31":    "https://tfac02lab31.infra.lab.corp",
    "PROD1DC1": "https://tfac02gam12.infra.corp",
    "PROD1DC2": "https://tfac02mes1b.infra.corp",
    "PROD2DC1": "https://tf2ac02gam12.infra.corp",
    "PROD2DC2": "https://tf2ac02mes1b.infra.corp",
}

# ---------- regex ----------
RE_ETH        = re.compile(r"^eth(\d+)(?:/(\d+))?(?:/(\d+))?$", re.I)
RE_NUM        = re.compile(r"^(\d+)\s*/\s*(\d+)(?:\s*/\s*(\d+))?$")
RE_PATHEP     = re.compile(r"pathep-\[(.+?)\]", re.I)
RE_PO         = re.compile(r"^po(\d+)$", re.I)
RE_NODE       = re.compile(r"/paths-(\d+)(?:/|$)")
RE_VPC        = re.compile(r"/protpaths-(\d+)-(\d+)(?:/|$)")
RE_NODE_DN    = re.compile(r"/node-(\d+)/")
RE_AGGR       = re.compile(r"/aggr-\[(.+?)\]")
# FIX #9: broadened to match any interface name inside phys-[...], not just eth-prefixed
RE_PHYS       = re.compile(r"phys-\[([^\]]+)\]", re.I)
RE_RSACC      = re.compile(r"^(.+?)/rsaccPortP-")
RE_RTACC      = re.compile(r"^(.+?)/rtaccPortP-")
RE_AAEP_DN    = re.compile(r"^(uni/infra/attentp-[^/]+)", re.I)

# ---------- utils ----------
def L(x): return x if isinstance(x, list) else ([] if x is None else [x])

def ior(x):
    try: return int(x)
    except: return None

def norm_dn(s: str) -> str:
    if not s: return ""
    s = s.strip().replace(" ", "").lower()
    return s[:-1] if s.endswith("/") else s

def norm_agg(s: str) -> str:
    if not s: return ""
    s = s.strip().lower()
    m = RE_PO.match(s)
    return f"po{int(m.group(1))}" if m else s

def norm_if(s: str) -> str:
    if not s: return ""
    s = s.strip()
    m = RE_PATHEP.search(s)
    if m: s = m.group(1).strip()
    s = s.lower()
    m = RE_ETH.match(s)
    if m:
        c,p,sp = m.groups()
        if sp: return f"eth{int(c)}/{int(p)}/{int(sp)}"
        if p:  return f"eth{int(c)}/{int(p)}"
        return f"eth{int(c)}"
    m = RE_NUM.match(s)
    if m:
        c,p,sp = m.groups()
        if sp: return f"eth{int(c)}/{int(p)}/{int(sp)}"
        return f"eth{int(c)}/{int(p)}"
    m = RE_PO.match(s)
    return f"po{int(m.group(1))}" if m else s

def if_sort_key(s):
    m = RE_ETH.match(s)
    if not m: return (9999, 9999, 9999, s)
    c,p,sp = m.groups()
    return (int(c), int(p) if p else 0, int(sp) if sp else 0, "")

def iter_children(root):
    """Shallow (one-level) child iterator — avoids unintended deep re-processing."""
    for ch in (root.get("children") or []):
        if not isinstance(ch, dict) or not ch:
            continue
        k = next(iter(ch))
        yield k, ch[k]

def iter_children_deep(root):
    """Deep child iterator — use only where full subtree traversal is required."""
    st = root.get("children") or []
    i = 0
    while i < len(st):
        ch = st[i]; i += 1
        if not isinstance(ch, dict) or not ch: continue
        k = next(iter(ch)); n = ch[k]; yield k, n
        sub = n.get("children")
        if sub: st.extend(sub)

# ---------- APIC ----------
class APIC:
    """
    Optimized APIC client with:
      - robust retries/backoff
      - optional HTTP log (for debugging)
      - paginated class queries
      - parallel subtree DN fetching (chunked to avoid connection exhaustion — Fix #6)
      - configurable AAA login domain (Fix #11)
    """
    def __init__(self, host, user, pwd, domain="Telco_Cloud", verify=False, http_log=False,
                 class_workers=8, subtree_workers=32, page_size=1000, timeout=60,
                 subtree_chunk=500):
        if not host.startswith("http"): host = "https://" + host
        self.url = host.rstrip("/")
        self.user = user
        self.pwd = pwd
        self.domain = domain          # FIX #11: configurable domain
        self.verify = verify
        self.http_log = http_log
        self.class_workers = max(1, int(class_workers))
        self.subtree_workers = max(1, int(subtree_workers))
        self.page_size = max(200, int(page_size))
        self.timeout = max(10, int(timeout))
        self.subtree_chunk = max(50, int(subtree_chunk))  # FIX #6

        s = requests.Session()
        r = Retry(
            total=5, backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods={"GET","POST"},
        )
        a = HTTPAdapter(max_retries=r, pool_maxsize=max(64, 2*(self.class_workers + self.subtree_workers)))
        s.mount("https://", a); s.mount("http://", a)
        s.headers.update({"Accept": "application/json"})
        self.sess = s

        # FIX (original): only wrap request logger when http_log is enabled
        if http_log:
            orig = self.sess.request
            def logged_request(method, url, **kwargs):
                print(f"[REQUEST] {method.upper()} {url}")
                if "params" in kwargs: print(f"  params={kwargs['params']}")
                if "json" in kwargs:   print(f"  json={kwargs['json']}")
                return orig(method, url, **kwargs)
            self.sess.request = logged_request

    def login(self):
        # FIX #11: use self.domain instead of hardcoded "Telco_Cloud"
        payload = {"aaaUser": {"attributes": {"name": f"apic:{self.domain}\\{self.user}", "pwd": self.pwd}}}
        r = self.sess.post(f"{self.url}/api/aaaLogin.json", json=payload, verify=self.verify, timeout=20)
        r.raise_for_status()
        if "APIC-cookie" not in self.sess.cookies:
            raise RuntimeError("APIC-cookie missing after login")

    def _cookie_expired(self, response):
        if response.status_code in (401, 403):
            try:
                data = response.json()
                imdata = data.get("imdata", [])
                if imdata and "error" in imdata[0]:
                    text = imdata[0]["error"]["attributes"].get("text", "").lower()
                    if any(k in text for k in ("token", "expired", "invalid", "not authorized", "login")):
                        return True
            except Exception:
                pass
            c = self.sess.cookies.get("APIC-cookie", None)
            if c is None or not str(c).strip():
                return True
        return False

    def _request_with_reauth(self, method, url, **kwargs):
        for _attempt in range(3):
            r = self.sess.request(method, url, **kwargs)
            if r.status_code < 400:
                return r
            if self._cookie_expired(r):
                print("⚠️  APIC session expired — performing re-login...")
                self.login()
                continue
            r.raise_for_status()
        raise RuntimeError("Repeated authentication failures while accessing APIC.")

    def class_query_all(self, cls, query_params=None, order_by_dn=True):
        out = []
        page = 0
        while True:
            u = f"{self.url}/api/class/{cls}.json"
            params = {"page-size": self.page_size, "page": page}
            if query_params:
                params.update(query_params)
            if order_by_dn:
                params["order-by"] = f"{cls}.dn|asc"
            r = self._request_with_reauth("GET", u, params=params, verify=self.verify, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            rows = data.get("imdata") or []  # FIX #12: already a list, no L() needed
            if not rows: break
            out.extend(rows)
            if len(rows) < self.page_size: break
            page += 1
        return out

    def fetch_dns(self, cls):
        res = []
        page = 0
        while True:
            url = f"{self.url}/api/class/{cls}.json"
            params = {"page-size": self.page_size, "page": page, "order-by": f"{cls}.dn|asc"}
            r = self._request_with_reauth("GET", url, params=params, verify=self.verify, timeout=self.timeout)
            r.raise_for_status()
            rows = r.json().get("imdata") or []  # FIX #12
            if not rows: break
            for mo in rows:
                if cls in mo:
                    res.append(mo[cls]["attributes"]["dn"])
            if len(rows) < self.page_size: break
            page += 1
        return res

    def fetch_subtrees(self, dns, query=""):
        """
        FIX #6: Chunked subtree fetching to avoid exhausting APIC connections
        on large fabrics with thousands of DNs.
        """
        if not dns: return []
        out = []

        def one(dn):
            u = f"{self.url}/api/mo/{dn}.json"
            if query: u += f"?{query}"
            try:
                r = self._request_with_reauth("GET", u, verify=self.verify, timeout=self.timeout)
                r.raise_for_status()
                return r.json().get("imdata") or []  # FIX #12
            except Exception as exc:
                print(f"  [WARN] fetch_subtrees: failed to fetch '{dn}': {exc}")
                return []

        # Single executor across all chunks to avoid per-chunk startup/teardown overhead.
        # Chunks are still submitted sequentially to avoid flooding APIC (Fix #6).
        with ThreadPoolExecutor(max_workers=self.subtree_workers) as ex:
            for i in range(0, len(dns), self.subtree_chunk):
                chunk = dns[i : i + self.subtree_chunk]
                fs = [ex.submit(one, d) for d in chunk]
                for f in as_completed(fs):
                    out.extend(f.result())
        return out

# ---------- infra collectors ----------
def build_port_inventory(api_data, mode="base"):
    per_node_ids = defaultdict(list)
    for mo in api_data.get("l1PhysIf", []):  # FIX #12: already a list
        li = mo.get("l1PhysIf")
        if not li:
            continue
        a  = li["attributes"]
        dn = a.get("dn", "") or ""
        m  = RE_NODE_DN.search(dn)
        if not m:
            continue
        node  = m.group(1)
        iface = norm_if(a.get("id", ""))
        if not iface.startswith("eth"):
            continue
        per_node_ids[node].append(iface)

    total_ports_by_node = {}
    details_by_node     = {}

    for node, ifs in per_node_ids.items():
        base_ports = set()
        lane_ports = set()

        children_by_base = defaultdict(set)
        bases_seen       = set()

        for i in ifs:
            parts = i.replace("eth", "").split("/")
            if len(parts) == 2:
                base = f"eth{int(parts[0])}/{int(parts[1])}"
                bases_seen.add(base)
            elif len(parts) == 3:
                base = f"eth{int(parts[0])}/{int(parts[1])}"
                lane = f"eth{int(parts[0])}/{int(parts[1])}/{int(parts[2])}"
                children_by_base[base].add(lane)
            else:
                continue

        for base in bases_seen | set(children_by_base.keys()):
            lanes = children_by_base.get(base)
            if lanes:
                lane_ports |= lanes
            else:
                lane_ports.add(base)

        base_ports = bases_seen | set(children_by_base.keys())

        if mode == "lanes":
            count = len(lane_ports)
        else:
            count = len(base_ports)

        total_ports_by_node[node] = count
        details_by_node[node] = {"base_ports": base_ports, "lane_ports": lane_ports}

    return total_ports_by_node, details_by_node

def collect_static_from_epgs(epg_full_list):
    """
    FIX #1: Use shallow iter_children (one level only) so that in the fallback
    path (rsp-subtree=children) we don't accidentally deep-walk and re-process
    nested objects. fvRsPathAtt is always a direct child of fvAEPg/fvEPg.
    """
    st = defaultdict(lambda: defaultdict(set))

    def add_from_attrs(a):
        enc = a.get("encap", "")
        if not enc or not enc.startswith("vlan-"):
            return

        dn  = a.get("dn", "") or ""
        tdn = a.get("tDn", "") or ""
        hay = tdn or dn

        m_if = RE_PATHEP.search(hay)
        if not m_if:
            return
        iface = norm_if(m_if.group(1))

        m_vpc = RE_VPC.search(hay)
        if m_vpc:
            nodes = {m_vpc.group(1), m_vpc.group(2)}
        else:
            m_node = RE_NODE.search(hay)
            nodes = {m_node.group(1)} if m_node else set()

        for n in nodes:
            st[n][iface].add(enc)

    for mo in epg_full_list:
        if not isinstance(mo, dict) or not mo:
            continue
        k = next(iter(mo.keys()))
        epg = mo.get(k)
        if not epg:
            continue
        # FIX #1: shallow iteration — fvRsPathAtt is always a direct child
        for ck, ch in iter_children(epg):
            if ck == "fvRsPathAtt":
                a = ch.get("attributes", {})
                if a:
                    add_from_attrs(a)

    return st

def expand_node_blk(a):
    f = ior(a.get("from_") or a.get("from")); t = ior(a.get("to_") or a.get("to"))
    return {str(x) for x in range(f, t+1)} if f is not None and t is not None else set()

def nodep_to_nodes(node_tree):
    out = {}
    for mo in node_tree:  # FIX #12
        if "infraNodeP" not in mo: continue
        np = mo["infraNodeP"]
        dn = norm_dn((np.get("attributes") or {}).get("dn", ""))
        if not dn: continue
        nodes = set()
        for k, n in iter_children_deep(np):
            if k == "infraLeafS":
                for ck, blk in iter_children(n):
                    if ck == "infraNodeBlk": nodes |= expand_node_blk(blk["attributes"])
            elif k == "infraNodeBlk":
                nodes |= expand_node_blk(n["attributes"])
        out[dn] = nodes
    return out

def accport_to_nodes(api_data, node_map):
    m = defaultdict(set)
    for mo in api_data.get("infraRsAccPortP", []):  # FIX #12
        a = mo["infraRsAccPortP"]["attributes"]; acc = norm_dn(a.get("tDn")); dn = a.get("dn", ""); r = RE_RSACC.match(dn)
        np = norm_dn(r.group(1)) if r else None
        if acc and np in node_map: m[acc] |= node_map[np]
    for mo in api_data.get("infraRtAccPortP", []):  # FIX #12
        a = mo["infraRtAccPortP"]["attributes"]; dn = a.get("dn", ""); r = RE_RTACC.match(dn)
        acc = norm_dn(r.group(1)) if r else None; np = norm_dn(a.get("tDn"))
        if acc and np in node_map: m[acc] |= node_map[np]
    return m

def expand_port_blk(a, debug=False):
    """FIX #10: emit warning in debug mode when infraPortBlk has missing/malformed fields."""
    fc, tc, fp, tp = ior(a.get("fromCard")), ior(a.get("toCard")), ior(a.get("fromPort")), ior(a.get("toPort"))
    if None in (fc, tc, fp, tp):
        if debug:
            print(f"  [WARN] expand_port_blk: missing field(s) in infraPortBlk attrs: {a}")
        return set()
    return {f"eth{c}/{p}" for c in range(fc, tc+1) for p in range(fp, tp+1)}

def expand_subport_blk(a, debug=False):
    """FIX #10: emit warning in debug mode when infraSubPortBlk has missing/malformed fields."""
    fc, tc, fp, tp = ior(a.get("fromCard")), ior(a.get("toCard")), ior(a.get("fromPort")), ior(a.get("toPort"))
    fsp, tsp = ior(a.get("fromSubPort")), ior(a.get("toSubPort"))
    if None in (fc, tc, fp, tp, fsp, tsp):
        if debug:
            print(f"  [WARN] expand_subport_blk: missing field(s) in infraSubPortBlk attrs: {a}")
        return set()
    return {f"eth{c}/{p}/{sp}" for c in range(fc, tc+1) for p in range(fp, tp+1) for sp in range(fsp, tsp+1)}

def pg_to_ifaces(acc_tree, acc_to_nodes, debug=False):
    res = defaultdict(set)
    for mo in acc_tree:  # FIX #12
        if "infraAccPortP" not in mo: continue
        app = mo["infraAccPortP"]; dn = norm_dn(app["attributes"]["dn"]); nodes = acc_to_nodes.get(dn, set())
        for k, hps in iter_children_deep(app):
            if k != "infraHPortS": continue
            tgt = None; ifs = set()
            for ck, ch in iter_children(hps):
                if ck in ("infraRsAccBaseGrp", "infraRsAccBndlSubgrp"):
                    tgt = norm_dn(ch["attributes"]["tDn"]); break
            if not tgt: continue
            for ck, ch in iter_children(hps):
                if ck == "infraPortBlk":
                    ifs |= {norm_if(i) for i in expand_port_blk(ch["attributes"], debug=debug)}
                elif ck == "infraSubPortBlk":
                    ifs |= {norm_if(i) for i in expand_subport_blk(ch["attributes"], debug=debug)}

            if nodes:
                for n in nodes:
                    for f in ifs: res[tgt].add((str(n), f))
            else:
                for f in ifs: res[tgt].add(("?", f))
    return res

def aaep_vlans(api_data):
    """
    FIX #2: Deduplicated processing of infraRsFuncToEpg.
    Previously the flat class list AND the subtree children AND infraGeneric
    children were all iterated separately, causing triple processing.
    Now: subtree children are the single source of truth; the flat class
    list is used only as a fallback for records that don't appear as children.
    """
    out = defaultdict(set)

    # Primary: process from infraAttEntityP subtrees (includes infraGeneric children)
    seen_rs_dns = set()

    for mo in api_data.get("infraAttEntityP", []):
        x = mo.get("infraAttEntityP")
        if not x: continue
        aaep_dn = norm_dn(x["attributes"]["dn"])
        for k, n in iter_children(x):
            if k in ("infraRsFuncToEpg", "infraRsFuncToVirtualLIfPAttEntPCont"):
                e = n["attributes"].get("encap")
                rs_dn = n["attributes"].get("dn", "")
                seen_rs_dns.add(norm_dn(rs_dn))
                if e and e.startswith("vlan-"): out[aaep_dn].add(e)
            elif k == "infraGeneric":
                for gk, gn in iter_children(n):
                    if gk in ("infraRsFuncToEpg", "infraRsFuncToVirtualLIfPAttEntPCont"):
                        e = gn["attributes"].get("encap")
                        rs_dn = gn["attributes"].get("dn", "")
                        seen_rs_dns.add(norm_dn(rs_dn))
                        if e and e.startswith("vlan-"): out[aaep_dn].add(e)

    # FIX #2: process infraGeneric flat list only for records not already seen above
    for mo in api_data.get("infraGeneric", []):
        x = mo.get("infraGeneric")
        if not x: continue
        d = norm_dn(x["attributes"]["dn"])
        parent = norm_dn("/".join(d.split("/")[:-1]))
        if not parent.startswith("uni/infra/attentp-"): continue
        for k, n in iter_children(x):
            if k in ("infraRsFuncToEpg", "infraRsFuncToVirtualLIfPAttEntPCont"):
                rs_dn = norm_dn(n["attributes"].get("dn", ""))
                if rs_dn in seen_rs_dns:
                    continue  # already processed from subtree
                e = n["attributes"].get("encap")
                seen_rs_dns.add(rs_dn)
                if e and e.startswith("vlan-"): out[parent].add(e)

    # FIX #2: flat class fallback — only for records not seen in any subtree
    for cls in ("infraRsFuncToEpg", "infraRsFuncToVirtualLIfPAttEntPCont"):
        for mo in api_data.get(cls, []):
            rel = mo.get(cls)
            if not rel: continue
            a = rel["attributes"]
            rs_dn = norm_dn(a.get("dn", "") or a.get("rn", ""))
            if rs_dn in seen_rs_dns:
                continue  # FIX #2: skip already-processed records
            enc = a.get("encap", ""); dn = a.get("dn", "") or a.get("rn", "")
            if not (enc and enc.startswith("vlan-") and dn): continue
            m = RE_AAEP_DN.search(dn)
            if m:
                aaep_dn = norm_dn(m.group(1))
                seen_rs_dns.add(rs_dn)
                out[aaep_dn].add(enc)

    return out

def build_epg_to_bd(api_data):
    epg_to_bd = {}
    for cls in ("fvAEPg", "fvEPg"):
        for mo in api_data.get(cls, []):  # FIX #12
            epg = mo.get(cls)
            if not epg: continue
            epg_dn = norm_dn(epg["attributes"]["dn"])
            bd_dn = None
            for k, n in iter_children(epg):
                if k == "fvRsBd":
                    bd_dn = norm_dn(n["attributes"].get("tDn"))
                    break
            if bd_dn:
                epg_to_bd[epg_dn] = bd_dn
    return epg_to_bd

def vlan_to_bd(api_data):
    m = defaultdict(set)
    epg_to_bd = build_epg_to_bd(api_data)

    for cls in ("fvAEPg", "fvEPg"):
        for mo in api_data.get(cls, []):  # FIX #12
            epg = mo.get(cls)
            if not epg: continue
            epg_dn = norm_dn(epg["attributes"]["dn"])
            bd_dn = epg_to_bd.get(epg_dn)
            if not bd_dn:
                continue
            for k, n in iter_children(epg):
                if k == "fvRsPathAtt":
                    enc = (n["attributes"].get("encap") or "")
                    if enc.startswith("vlan-"):
                        m[enc].add(bd_dn)

    for mo in api_data.get("infraRsFuncToEpg", []):  # FIX #12
        rel = mo.get("infraRsFuncToEpg")
        if not rel: continue
        a = rel["attributes"]; enc = a.get("encap", "")
        if not enc or not enc.startswith("vlan-"): continue
        # FIX #3: guard against missing tDn
        tdn = a.get("tDn")
        if not tdn:
            continue
        epg_dn = norm_dn(tdn)
        if not epg_dn:
            continue
        bd_dn = epg_to_bd.get(epg_dn)
        if bd_dn:
            m[enc].add(bd_dn)

    for mo in api_data.get("infraAttEntityP", []):  # FIX #12
        att = mo.get("infraAttEntityP")
        if not att: continue
        for k, n in iter_children(att):
            if k == "infraGeneric":
                for gk, gn in iter_children(n):
                    if gk == "infraRsFuncToEpg":
                        a = gn["attributes"]; enc = a.get("encap", "")
                        if enc.startswith("vlan-"):
                            # FIX #3: guard against missing tDn
                            tdn = a.get("tDn")
                            if not tdn:
                                continue
                            epg_dn = norm_dn(tdn)
                            if not epg_dn:
                                continue
                            bd_dn = epg_to_bd.get(epg_dn)
                            if bd_dn:
                                m[enc].add(bd_dn)

    return m

def bd_l3_map(api_data, debug=False):
    FALSE = {"no", "false", "disabled", "off", "0"}

    def norm(v: str) -> str:
        return (v or "").strip().lower()

    def is_l2(attrs: dict, has_subnet: bool):
        """
        A BD is L2 (weight=1 in PxV) when:
          - unicastRoute is explicitly disabled, AND
          - no subnets are configured.

        The flood-mode attributes (unkMacUcastAct, arpFlood, multiDstPktAct)
        describe *how* a BD floods but do not affect the L2/L3 PxV weight.
        Any BD with routing disabled and no subnets is hardware-L2 regardless
        of those settings.

        Everything else is L3 (weight=2): routing enabled, subnets present,
        or unicastRoute unset/unknown (conservative default).
        """
        if has_subnet:
            return False, "L3: fvSubnet present"
        u = norm(attrs.get("unicastRoute"))
        if u not in FALSE:
            return False, f"L3: unicastRoute='{u or 'unset'}' is not disabled"
        return True, "L2: unicastRoute disabled, no subnets"

    out = {}
    if debug:
        print("\n================= DEBUG: BD L2/L3 DETECTION (refined) =================")
    for mo in api_data.get("fvBD", []):  # FIX #12
        bd = mo.get("fvBD")
        if not bd: continue
        attrs = bd["attributes"]
        # FIX #13: store raw DN for output; use norm_dn only for map key
        raw_dn = attrs["dn"]
        dn = norm_dn(raw_dn)
        subnets = []
        for k, n in iter_children(bd):
            if k == "fvSubnet":
                subnets.append(n["attributes"].get("ip"))
        has_subnet = bool(subnets)

        l2, reason = is_l2(attrs, has_subnet)
        out[dn] = False if l2 else True   # False = L2, True = L3

        if debug:
            print(f"\nBD: {raw_dn}")  # FIX #13: print raw DN
            print(f"  unicastRoute     : {attrs.get('unicastRoute')}")
            print(f"  fvSubnet (count) : {len(subnets)}")
            if l2:
                print(f"  -> Classified as L2 — {reason}")
            else:
                print(f"  -> Classified as L3 — {reason}")

    if debug:
        print("=======================================================================\n")
    return out

def po_members(api_data):
    out = defaultdict(lambda: defaultdict(set))
    for mo in api_data.get("pcRsMbrIfs", []):  # FIX #12
        inner = mo.get("pcRsMbrIfs")
        if not inner: continue
        a = inner.get("attributes", {})
        if not a: continue
        dn = a.get("dn", "") or a.get("rn", ""); t = a.get("tDn", "")
        mn = RE_NODE_DN.search(dn) or RE_NODE_DN.search(t)
        if not mn: continue
        node = mn.group(1)
        ma = RE_AGGR.search(dn)
        if not ma: continue
        ag = norm_agg(ma.group(1))
        # FIX #9: RE_PHYS now matches any interface name, not just eth-prefixed
        me = RE_PHYS.search(dn) or RE_PHYS.search(t)
        if not me: continue
        eth = norm_if(me.group(1))
        out[node][ag].add(eth)
    return out

def logical_to_po(api_data):
    out = defaultdict(dict)
    for mo in api_data.get("pcAggrIf", []):  # FIX #12
        inner = mo.get("pcAggrIf")
        if not inner: continue
        a = inner.get("attributes", {})
        dn = a.get("dn", ""); mn = RE_NODE_DN.search(dn)
        if not mn: continue
        node = mn.group(1); name = norm_agg(a.get("name", "")); pc = a.get("pcId", "")
        if name and pc: out[node][name] = f"po{pc}"
    return out

def compute_pxv_per_port(static_pxv, aaep_pxv, vlan_to_bd, bd_l3_map,
                         po_by_node=None, l2h_by_node=None, debug=False):
    """
    FIX #4: Warn when "?" (unmapped) node entries are dropped.
    FIX #5: Warn when a BD DN is not found in bd_l3_map (defaults to L3/weight=2).
    PERF:   Pre-group aaep_pxv by node to avoid O(N×M) per-node scans.
    FIX: Logical interfaces (VPC/PC) are resolved to their physical eth member ports
         before PxV is summed so that VLANs are not double-counted (once on the
         logical interface and once on its eth members).  Only eth* ports are
         emitted in the result; the 'ports_used' count therefore reflects real
         physical ports, not logical bundles.
    """
    results = {}
    po_by_node  = po_by_node  or {}
    l2h_by_node = l2h_by_node or {}

    # Pre-group aaep_pxv by node for O(1) per-node lookup
    aaep_by_node = defaultdict(dict)
    for (n, iface), vlans in aaep_pxv.items():
        aaep_by_node[n][iface] = vlans

    # FIX #4: collect and warn about unmapped "?" entries
    unmapped = aaep_by_node.pop("?", {})
    if unmapped:
        print(f"  [WARN] {len(unmapped)} interface(s) have no node mapping (node='?') "
              f"and will be excluded from PxV calculation. "
              f"Check infraHPortS→infraRsAccBaseGrp/infraRsAccBndlSubgrp bindings.")
        if debug:
            for iface, vlans in sorted(unmapped.items()):
                print(f"    unmapped iface: {iface}  vlans={len(vlans)}")

    nodes = set(str(n) for n in static_pxv.keys() if str(n).isdigit())
    nodes |= set(n for n in aaep_by_node.keys() if str(n).isdigit())

    missing_bds_warned = set()  # FIX #5

    for node in sorted(nodes, key=lambda x: int(x)):
        node_po  = po_by_node.get(node, {})
        node_l2h = l2h_by_node.get(node, {})

        # Accumulate VLANs per *physical* eth port only.
        # Logical interfaces (VPC/PC/bundle names) are resolved to their member
        # eth ports so that VLANs are attributed to hardware ports exactly once.
        phys_vlans: dict[str, set] = defaultdict(set)

        all_ifaces = set(static_pxv.get(node, {}).keys()) | set(aaep_by_node.get(node, {}).keys())
        unresolved_logical = []

        for iface in all_ifaces:
            vlans = set()
            vlans |= static_pxv.get(node, {}).get(iface, set())
            vlans |= aaep_by_node.get(node, {}).get(iface, set())
            if not vlans:
                continue

            nf = norm_if(iface)
            if nf.startswith("eth"):
                phys_vlans[nf] |= vlans
            else:
                # Resolve logical (VPC/PC) → physical member ports
                mem = set()
                if nf in node_po:
                    mem |= node_po[nf]
                if not mem:
                    lg = norm_agg(nf)
                    po = node_l2h.get(lg)
                    if po and po in node_po:
                        mem |= node_po[po]
                eth_members = {e for e in mem if e.startswith("eth")}
                if eth_members:
                    for eth in eth_members:
                        phys_vlans[eth] |= vlans
                else:
                    unresolved_logical.append((iface, vlans))

        if unresolved_logical and debug:
            for iface, vlans in unresolved_logical:
                print(f"  [WARN] No eth members for logical iface '{iface}' on node {node} "
                      f"({len(vlans)} VLANs) — excluded from PxV.")

        node_data = {}
        node_total = 0

        for iface in sorted(phys_vlans.keys(), key=if_sort_key):
            vlans = phys_vlans[iface]

            bds = set()
            for vlan in vlans:
                for bd in vlan_to_bd.get(vlan, set()):
                    bds.add(bd)

            l2 = 0
            l3 = 0
            for bd in bds:
                if bd not in bd_l3_map:
                    # FIX #5: warn once per missing BD; default to L3 (conservative)
                    if bd not in missing_bds_warned:
                        print(f"  [WARN] BD '{bd}' not found in bd_l3_map — "
                              f"defaulting to L3 (weight=2). This inflates PxV. "
                              f"Check fvBD fetch coverage.")
                        missing_bds_warned.add(bd)
                    l3 += 1
                elif bd_l3_map[bd]:
                    l3 += 1
                else:
                    l2 += 1

            pxv_port = l2 + 2 * l3
            node_data[iface] = {
                "vlans": sorted(vlans),
                "bds": sorted(bds),
                "l2_bds": l2,
                "l3_bds": l3,
                "pxv": pxv_port,
            }
            node_total += pxv_port

        results[node] = {"per_port": node_data, "node_pxv": node_total}

    return results

# ---------- compute engine ----------
def compute(api, api_data, acc_tree, node_tree, static_pxv, totals_only, ports_override, pxv_limit,
            po_by_node, l2h_by_node, show_mapping=False, expand_logical=False, debug_pxv=False,
            total_ports_by_node=None, ports_mode="base"):

    leafs = {
        mo["fabricNode"]["attributes"]["id"]:
        mo["fabricNode"]["attributes"].get("name", "node-" + mo["fabricNode"]["attributes"]["id"])
        for mo in api_data.get("fabricNode", [])  # FIX #12
        if mo["fabricNode"]["attributes"].get("role") == "leaf"
    }

    node_map = nodep_to_nodes(node_tree)
    acc_map  = accport_to_nodes(api_data, node_map)
    pg_if    = pg_to_ifaces(acc_tree, acc_map, debug=debug_pxv)

    pg2aaep = {}
    for mo in api_data.get("policy_groups_full", []):
        k = next(iter(mo.keys())); pg = mo[k]; dn = norm_dn(pg["attributes"]["dn"])
        for ck, ch in iter_children(pg):
            if ck == "infraRsAttEntP":
                pg2aaep[dn] = norm_dn(ch["attributes"]["tDn"])

    aaep_vlan = aaep_vlans(api_data)
    aaep2ifs = defaultdict(set)
    for pgdn, entries in pg_if.items():
        tgt = pgdn if pgdn.startswith("uni/infra/attentp-") else pg2aaep.get(pgdn)
        if tgt:
            aaep2ifs[tgt].update(entries)

    aaep_pxv = defaultdict(set)
    for aaep_dn, entries in aaep2ifs.items():
        v = aaep_vlan.get(aaep_dn, set())
        for n, f in entries:
            aaep_pxv[(n, f)] |= v

    bd_l3  = bd_l3_map(api_data, debug=debug_pxv)
    v2bd   = vlan_to_bd(api_data)

    if debug_pxv:
        print("\n=== GLOBAL SANITY ===")
        total_bd = len(bd_l3)
        l3_count = sum(1 for v in bd_l3.values() if v is True)
        l2_count = sum(1 for v in bd_l3.values() if v is False)
        print(f"Total BD entries in bd_l3: {total_bd} (L3={l3_count} / L2={l2_count})")
        sample_bds = list(bd_l3.keys())[:5]
        print("Sample bd_l3 keys:", sample_bds)
        sample_vlans = list(v2bd.keys())[:10]
        print("Sample VLAN->BD from v2bd:")
        for sv in sample_vlans:
            print(f"  {sv} -> {sorted(v2bd[sv])}")
        print("======================\n")

    # Compute per-port PxV ONCE for the whole fabric.
    # po_by_node and l2h_by_node are passed so that logical interfaces
    # (VPC/PC) are resolved to their physical eth members before PxV is summed,
    # preventing double-counting of VLANs on both the logical and physical ports.
    per_port_pxv = compute_pxv_per_port(
        static_pxv=static_pxv,
        aaep_pxv=aaep_pxv,
        vlan_to_bd=v2bd,
        bd_l3_map=bd_l3,
        po_by_node=po_by_node,
        l2h_by_node=l2h_by_node,
        debug=debug_pxv,
    )

    # Build hw_stats ONCE
    hw_stats = {}
    for nid, rec in per_port_pxv.items():
        hw_stats[nid] = {
            "ports_used": len(rec["per_port"]),
            "l2_bds": sum(x["l2_bds"] for x in rec["per_port"].values()),
            "l3_bds": sum(x["l3_bds"] for x in rec["per_port"].values()),
            "pxv_value": rec["node_pxv"],
        }

    # Pre-group aaep_pxv by node for O(1) per-leaf lookup (avoids O(N×M) scan)
    aaep_by_node = defaultdict(dict)
    for (n, iface), vlans in aaep_pxv.items():
        aaep_by_node[n][iface] = vlans

    for leaf_node, leaf_name in sorted(leafs.items(), key=lambda x: int(x[0])):
        node_aaep = aaep_by_node.get(leaf_node, {})
        all_if = set(static_pxv.get(leaf_node, {}).keys()) | set(node_aaep.keys())
        active = set()
        node_po  = po_by_node.get(leaf_node, {})
        node_l2h = l2h_by_node.get(leaf_node, {})

        pathep_cov = {}
        inh_by_eth = defaultdict(set)
        inh_src    = defaultdict(lambda: defaultdict(set))
        logical_only = {}

        for iface in all_if:
            vset = static_pxv.get(leaf_node, {}).get(iface, set()) | node_aaep.get(iface, set())
            if not vset: continue
            nf = norm_if(iface)
            if nf.startswith("eth"):
                active.add(nf); continue
            mem = set()
            if nf in node_po: mem |= node_po[nf]
            if not mem:
                lg = norm_agg(nf); po = node_l2h.get(lg)
                if po and po in node_po: mem |= node_po[po]
            if show_mapping and not nf.startswith("eth"):
                lg = norm_agg(nf); info = pathep_cov.setdefault(lg, {"mapped": False, "po": None, "members": set()})
                po = node_l2h.get(lg)
                if po: info["po"] = po
                if mem:
                    info["mapped"] = True
                    info["members"] = set(sorted(mem))
            for e in mem:
                if e.startswith("eth"): active.add(e)
            if expand_logical and not nf.startswith("eth"):
                lg = norm_agg(nf); s_only = static_pxv.get(leaf_node, {}).get(nf, set())
                if s_only and mem:
                    logical_only[lg] = set(s_only)
                    for e in mem:
                        inh_by_eth[e] |= s_only
                        inh_src[e][lg] |= s_only

        if ports_override:
            ports = ports_override
        else:
            if ports_mode == "active":
                ports = len(active)
            else:
                ports = (total_ports_by_node or {}).get(leaf_node, 0)

        if debug_pxv:
            print("\n================ PXV DEBUG (per-port) =====================")
            print(f"Node {leaf_node} ({leaf_name})")
            port_rec = per_port_pxv.get(leaf_node, {"per_port": {}, "node_pxv": 0})

            for iface, rec in sorted(port_rec["per_port"].items(), key=lambda kv: if_sort_key(kv[0])):
                print(
                    f"  {iface:16s} "
                    f"L2={rec['l2_bds']:4d}  "
                    f"L3={rec['l3_bds']:4d}  "
                    f"PxV={rec['pxv']:4d}  "
                    f"VLANs={len(rec['vlans']):4d}"
                )
            print(f"  -> Node PxV = {port_rec['node_pxv']}")
            print("==========================================================\n")

        if show_mapping:
            print(f"\n[Leaf {leaf_name} (Node {leaf_node})] Mapping")
            for lg, po in sorted(l2h_by_node.get(leaf_node, {}).items()):
                mem = sorted(po_by_node.get(leaf_node, {}).get(po, set()))
                print(f"  {lg:28s} -> {po:6s} -> {{{', '.join(mem)}}}")
            print("\nPathep coverage")
            for lg, info in sorted(pathep_cov.items()):
                po = info['po'] or '-'; mem = ", ".join(sorted(info['members']))
                st = "OK" if info['mapped'] else "MISSING"
                print(f"  {lg:28s} po={po:5s} mapped={st:7s} members={{{mem}}}")

        if expand_logical and logical_only:
            print(f"\n[Leaf {leaf_name} (Node {leaf_node})] Logical->Members")
            for lg, vl in sorted(logical_only.items()):
                po = l2h_by_node.get(leaf_node, {}).get(lg, lg)
                mem = sorted(po_by_node.get(leaf_node, {}).get(po, set()), key=if_sort_key)
                print(f"  {lg:20s} static={len(vl):3d} -> {{{', '.join(mem)}}}")
            print("\nPer-port inherited")
            for eth, v in sorted(inh_by_eth.items(), key=lambda x: if_sort_key(x[0])):
                srcs = ", ".join(sorted(inh_src[eth].keys()))
                print(f"  {eth:12s}: {len(v)} via {srcs}")

    return leafs, static_pxv, aaep_pxv, hw_stats

# ---------- output ----------
def build_json(leafs, static_pxv, aaep_pxv, hw_stats, totals_only, pxv_limit):
    # Pre-group for O(1) per-node lookup
    aaep_by_node = defaultdict(dict)
    for (n, iface), vlans in aaep_pxv.items():
        aaep_by_node[n][iface] = vlans

    out = {"nodes": {}}
    for node, host in leafs.items():
        ne = {"hostname": host}
        node_aaep = aaep_by_node.get(node, {})
        ifaces = set(static_pxv.get(node, {}).keys()) | set(node_aaep.keys())
        st = at = ut = 0
        if not totals_only: ne["interfaces"] = {}
        for iface in sorted(ifaces, key=if_sort_key):
            s = static_pxv.get(node, {}).get(iface, set())
            a = node_aaep.get(iface, set())
            u = s | a
            st += len(s); at += len(a); ut += len(u)
            if not totals_only:
                ne["interfaces"][iface] = {
                    "static": sorted(s), "static_count": len(s),
                    "aaep": sorted(a), "aaep_count": len(a),
                    "union": sorted(u), "union_count": len(u)
                }
        ne["totals"] = {"static_total": st, "aaep_total": at, "union_total": ut}
        hw = hw_stats.get(node, {"ports_used": 0, "l2_bds": 0, "l3_bds": 0, "pxv_value": 0})
        ne["hardware_pxv"] = {
            "ports_used": hw["ports_used"],
            "l2_bds": hw["l2_bds"],
            "l3_bds": hw["l3_bds"],
            "pxv_value": hw["pxv_value"],
            "limit": pxv_limit,
            "within_limit": hw["pxv_value"] <= pxv_limit,
            "note": "PxV = SUM_over_ports( L2 + 2×L3 )  (strict per-port calculation)"
        }
        out["nodes"][node] = ne
    return out

def print_text(leafs, static_pxv, aaep_pxv, hw_stats, totals_only, pxv_limit):
    # Pre-group for O(1) per-node lookup
    aaep_by_node = defaultdict(dict)
    for (n, iface), vlans in aaep_pxv.items():
        aaep_by_node[n][iface] = vlans

    print("\n==============================================")
    print("          ACI PxV REPORT (Selector-Based)")
    print("==============================================\n")
    for node, host in sorted(leafs.items(), key=lambda x: int(x[0])):
        print(f"\nLeaf {host} (Node {node})\n")
        node_aaep = aaep_by_node.get(node, {})
        ifs = sorted(set(static_pxv.get(node, {}).keys()) | set(node_aaep.keys()), key=if_sort_key)
        st = at = ut = 0
        for f in ifs:
            s = static_pxv.get(node, {}).get(f, set()); a = node_aaep.get(f, set()); u = s | a
            st += len(s); at += len(a); ut += len(u)
            if not totals_only:
                print(f"  {f:30s} static={len(s):4d} aaep={len(a):4d} union={len(u):4d}")
        print(f"\n  >>> STATIC PxV = {st}")
        print(f"  >>> AAEP   PxV = {at}")
        print(f"  >>> UNION  PxV = {ut}")

        hw = hw_stats.get(node, {"pxv_value": 0, "ports_used": 0, "l2_bds": 0, "l3_bds": 0})
        print(f"  >>> HW PxV (per-port) = {hw['pxv_value']}  "
              f"[{'OK' if hw['pxv_value'] <= pxv_limit else 'EXCEEDS LIMIT'} ≤ {pxv_limit}]")
        print(f"      Ports counted: {hw['ports_used']}, "
              f"L2 BDs sum: {hw['l2_bds']}, L3 BDs sum: {hw['l3_bds']}")
        print("      Formula: PxV = Σ_per_port( L2 + 2×L3 )")
        print("--------------------------------------------------")

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(prog="aci-pxv", add_help=True)
    p.add_argument("--apic")
    p.add_argument("--env")
    p.add_argument("--user", default=os.getenv("APIC_USER"))
    p.add_argument("--password", default=os.getenv("APIC_PASS"))
    # FIX #11: configurable AAA login domain (was hardcoded as "Telco_Cloud")
    p.add_argument("--domain", default=os.getenv("APIC_DOMAIN", "Telco_Cloud"),
                   help="AAA login domain (default: Telco_Cloud or $APIC_DOMAIN env var)")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--workers", type=int, default=40, help="Subtree concurrency (default 40)")
    p.add_argument("--subtree-chunk", type=int, default=500,
                   help="Max simultaneous subtree fetches per batch (default 500, Fix #6)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--totals-only", action="store_true")
    p.add_argument("--static-mode", choices=["per-node", "all"], default="all",
                   help="Preserved for compatibility; 'all' is now optimized")
    p.add_argument("--ports", type=int, default=0)
    p.add_argument("--pxv-limit", type=int, default=168000)
    p.add_argument("--show-mapping", action="store_true")
    p.add_argument("--expand-logical", action="store_true")
    p.add_argument("--debug-pxv", action="store_true")
    p.add_argument("--page-size", type=int, default=1000,
                   help="APIC API page-size for pagination (default 1000)")
    p.add_argument("--http-log", action="store_true", help="Print HTTP requests (debug)")
    p.add_argument(
        "--ports-mode",
        choices=["base", "lanes", "active"],
        default="base",
        help="How to count ports for PxV: 'base' (default), 'lanes' (count breakout lanes), "
             "or 'active' (legacy behavior: only ports with VLANs)"
    )
    return p.parse_args()

# ---------- main ----------
def main():
    a = parse_args()
    if a.apic: host = a.apic
    elif a.env:
        env = a.env.upper()
        if env not in APIC_ENV:
            print(f"Unknown env: {a.env}"); sys.exit(1)
        host = APIC_ENV[env]
    else:
        print("Specify --apic or --env"); sys.exit(1)

    if not a.user: print("Missing --user"); sys.exit(1)
    pwd = a.password or getpass.getpass("APIC Password: ")
    if not pwd: print("No password"); sys.exit(1)

    class_workers   = min(8, max(4, a.workers // 4))
    subtree_workers = a.workers
    api = APIC(
        host, a.user, pwd,
        domain=a.domain,           # FIX #11
        verify=a.verify,
        http_log=a.http_log,
        class_workers=class_workers,
        subtree_workers=subtree_workers,
        page_size=a.page_size,
        timeout=60,
        subtree_chunk=a.subtree_chunk,  # FIX #6
    )
    api.login()

    t0 = time.time()

    flat_classes = [
        "fabricNode",
        "infraRsAccPortP", "infraRtAccPortP",
        "pcAggrIf", "pcRsMbrIfs",
        "infraGeneric",
        "infraRsFuncToEpg", "infraRsFuncToVirtualLIfPAttEntPCont",
        "l1PhysIf",
    ]

    # FIX #8: fetch all flat classes in parallel
    data = {}
    print(f"Fetching {len(flat_classes)} class queries in parallel (workers={class_workers})...")
    with ThreadPoolExecutor(max_workers=class_workers) as ex:
        futures = {ex.submit(api.class_query_all, cls): cls for cls in flat_classes}
        for f in as_completed(futures):
            cls = futures[f]
            try:
                data[cls] = f.result()
            except Exception as e:
                print(f"  [WARN] class query failed for {cls}: {e}")
                data[cls] = []

    def fetch_full(cls, subtree_q):
        dns = api.fetch_dns(cls)
        return api.fetch_subtrees(dns, subtree_q)

    acc_tree  = fetch_full("infraAccPortP",
                           "rsp-subtree=full&rsp-prop-include=config-only&"
                           "rsp-subtree-class=infraHPortS,infraPortBlk,infraSubPortBlk,"
                           "infraRsAccBaseGrp,infraRsAccBndlSubgrp,infraRsAttEntP")
    node_tree = fetch_full("infraNodeP", "rsp-subtree=full")

    pg_acc  = fetch_full("infraAccPortGrp",  "rsp-subtree=full")
    pg_bndl = fetch_full("infraAccBndlGrp",  "rsp-subtree=full")
    data["policy_groups_full"] = pg_acc + pg_bndl

    data["fvBD"] = fetch_full("fvBD", "rsp-subtree=full&rsp-subtree-class=fvSubnet")

    fvA_full = fetch_full("fvAEPg", "rsp-subtree=full&rsp-subtree-class=fvRsBd,fvRsPathAtt,fvRsDomAtt")
    fvE_full = fetch_full("fvEPg",  "rsp-subtree=full&rsp-subtree-class=fvRsBd,fvRsPathAtt,fvRsDomAtt")
    data["fvAEPg"] = fvA_full
    data["fvEPg"]  = fvE_full

    data["infraAttEntityP"] = fetch_full(
        "infraAttEntityP",
        "rsp-subtree=full&"
        "rsp-subtree-class=infraGeneric,infraRsFuncToEpg,infraRsFuncToVirtualLIfPAttEntPCont"
    )

    static_pxv = collect_static_from_epgs(data["fvAEPg"] + data["fvEPg"])

    if not static_pxv:
        # Derive DNs from already-fetched objects; avoid redundant API calls
        epg_dns = []
        for mo in data["fvAEPg"] + data["fvEPg"]:
            if not mo: continue
            inner = next(iter(mo.values()), None)
            if inner:
                dn = (inner.get("attributes") or {}).get("dn")
                if dn: epg_dns.append(dn)
        epg_rs_only = api.fetch_subtrees(
            epg_dns,
            "rsp-subtree=children&rsp-subtree-class=fvRsPathAtt"
        )
        static_pxv = collect_static_from_epgs(epg_rs_only)

    po_by_node  = po_members(data)
    l2h_by_node = logical_to_po(data)

    total_ports_by_node, _port_details = build_port_inventory(data, mode=a.ports_mode)

    leafs, static_pxv, aaep_pxv, hw_stats = compute(
        api, data, acc_tree, node_tree,
        static_pxv=static_pxv, totals_only=a.totals_only,
        ports_override=a.ports, pxv_limit=a.pxv_limit,
        po_by_node=po_by_node, l2h_by_node=l2h_by_node,
        show_mapping=a.show_mapping, expand_logical=a.expand_logical,
        debug_pxv=a.debug_pxv,
        total_ports_by_node=total_ports_by_node,
        ports_mode=a.ports_mode,
    )

    if a.json:
        print(json.dumps(build_json(leafs, static_pxv, aaep_pxv, hw_stats, a.totals_only, a.pxv_limit), indent=2))
    else:
        print_text(leafs, static_pxv, aaep_pxv, hw_stats, a.totals_only, a.pxv_limit)

    t1 = time.time()
    print(f"\n[Done in {t1 - t0:0.1f}s] class_workers={class_workers} "
          f"subtree_workers={subtree_workers} page_size={a.page_size} "
          f"subtree_chunk={a.subtree_chunk}")

if __name__ == "__main__":
    main()
