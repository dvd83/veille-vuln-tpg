#!/usr/bin/env python3
"""Collecte structurée pour la veille vulnérabilités.

Sources (toutes via GitHub, seul accès réseau fiable depuis la tâche planifiée) :
  - Catalogue CISA KEV          : https://github.com/cisagov/kev-data
  - Liste officielle des CVE    : https://github.com/CVEProject/cvelistV5 (clone partiel)

Usage :
  python3 -I scripts/collect.py --work /tmp/veille-src --since 2026-11-19T07:00:00Z --out /tmp/candidats.json

Sortie : un JSON (hors du site public) avec
  kev.stats, kev.recent (ajouts 7 j), kev.due14 (échéances 14 j),
  cves.critical (CVSS >= 9 publiées dans la fenêtre),
  cves.watch (toutes CVE de la fenêtre dont l'éditeur/produit est dans la liste de surveillance, quel que soit le score),
  cves.kev_in_window (CVE de la fenêtre déjà au KEV).
Le script n'écrit rien dans public/.
"""
import argparse, datetime as dt, glob, json, os, subprocess, sys

WATCH = [  # éditeurs / produits courants dans une infra d'entreprise (minuscules, sous-chaînes)
    "microsoft", "windows", "exchange", "office", "outlook", "sharepoint", "azure", "entra",
    "red hat", "rhel", "openshift", "linux kernel", "kernel", "vmware", "broadcom", "vcenter", "esxi",
    "veeam", "citrix", "netscaler", "fortinet", "fortios", "fortigate", "cisco", "palo alto", "pan-os",
    "sonicwall", "check point", "ivanti", "f5", "big-ip", "juniper", "aruba", "hpe", "dell", "netapp",
    "synology", "commvault", "nutanix",
    "php", "openjdk", "oracle java", "java se", "python", "node.js", "nodejs", "openssl", "openssh",
    "apache", "httpd", "tomcat", "nginx", "log4j", "spring", "jenkins", "gitlab", "jetbrains", "teamcity",
    "atlassian", "confluence", "jira", "splunk", "elastic", "google chrome", "chrome", "chromium",
    "mozilla", "firefox", "edge", "adobe", "acrobat", "zoom", "teams", "mitel", "avaya", "kubernetes",
    "docker", "postgresql", "mysql", "mariadb", "mongodb", "redis", "keycloak", "openstack", "puppet",
    "ansible", "zabbix", "grafana", "sap", "oracle", "ibm", "trellix", "sophos", "crowdstrike", "trend micro",
]


def run(cmd, cwd=None, timeout=600):
    return subprocess.run(cmd, cwd=cwd, check=True, timeout=timeout, capture_output=True, text=True)


def clone_kev(work):
    d = os.path.join(work, "kev-data")
    if os.path.isdir(os.path.join(d, ".git")):
        run(["git", "pull", "-q", "--depth", "1"], cwd=d)
    else:
        run(["git", "clone", "-q", "--depth", "1", "https://github.com/cisagov/kev-data", d])
    return json.load(open(os.path.join(d, "known_exploited_vulnerabilities.json")))


def cve_path(cid):
    _, y, n = cid.split("-")
    return f"cves/{y}/{n[:-3]}xxx/{cid}.json"


def fetch_cvelist(work, since_iso):
    d = os.path.join(work, "cvelist")
    if not os.path.isdir(os.path.join(d, ".git")):
        os.makedirs(d, exist_ok=True)
        run(["git", "init", "-q"], cwd=d)
        run(["git", "remote", "add", "origin", "https://github.com/CVEProject/cvelistV5"], cwd=d)
        run(["git", "config", "core.sparseCheckout", "true"], cwd=d)
    sc = os.path.join(d, ".git", "info", "sparse-checkout")
    open(sc, "w").write("cves/deltaLog.json\n")
    run(["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", "main"], cwd=d)
    run(["git", "checkout", "-q", "-f", "FETCH_HEAD"], cwd=d)
    log = json.load(open(os.path.join(d, "cves", "deltaLog.json")))
    ids = set()
    for e in log:
        if e["fetchTime"] >= since_iso:
            for c in e.get("new", []) + e.get("updated", []):
                ids.add(c["cveId"])
    open(sc, "w").write("cves/deltaLog.json\n" + "".join(cve_path(i) + "\n" for i in sorted(ids)))
    run(["git", "read-tree", "-mu", "HEAD"], cwd=d, timeout=900)
    return d, log[0]["fetchTime"] if log else None, len(ids)


def best_score(rec):
    best, vec = None, None
    conts = [rec.get("containers", {}).get("cna", {})] + rec.get("containers", {}).get("adp", [])
    for c in conts:
        for m in c.get("metrics", []):
            for v in m.values():
                if isinstance(v, dict) and "baseScore" in v:
                    if best is None or v["baseScore"] > best:
                        best, vec = v["baseScore"], v.get("vectorString")
    return best, vec


def summarize(rec):
    m = rec["cveMetadata"]; cna = rec["containers"].get("cna", {})
    aff = cna.get("affected", []) or [{}]
    desc = next((x["value"] for x in cna.get("descriptions", []) if x.get("lang", "").startswith("en")), "")
    score, vec = best_score(rec)
    versions = []
    for a in aff[:3]:
        for v in a.get("versions", [])[:4]:
            s = v.get("version", "")
            if v.get("lessThan"): s += " < " + v["lessThan"]
            if v.get("lessThanOrEqual"): s += " <= " + v["lessThanOrEqual"]
            versions.append(f'{a.get("product","?")}: {s} ({v.get("status","")})')
    refs = [r["url"] for r in cna.get("references", [])][:4]
    return {
        "cve": m["cveId"], "published": m.get("datePublished", "")[:16],
        "vendor": aff[0].get("vendor", "?"), "product": aff[0].get("product", "?"),
        "title": cna.get("title") or desc[:120], "description": desc[:600],
        "cvss": score, "vector": vec, "versions": versions, "references": refs,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--since", required=True, help="début de fenêtre ISO UTC, ex. 2026-11-19T07:00:00Z")
    ap.add_argument("--out", required=True)
    ap.add_argument("--today", default=dt.date.today().isoformat())
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    today = dt.date.fromisoformat(a.today)
    since = a.since.replace("Z", "")
    out = {"generated": dt.datetime.now(dt.timezone.utc).isoformat(), "window_since": a.since, "errors": []}

    # --- KEV
    try:
        kev = clone_kev(a.work)
        v = kev["vulnerabilities"]
        D = dt.date.fromisoformat
        prev = today - dt.timedelta(days=1)
        while prev.weekday() >= 5: prev -= dt.timedelta(days=1)
        yesterday_days = {(today - dt.timedelta(days=k)).isoformat() for k in range(1, (today - prev).days + 1)}
        kev_ids = {x["cveID"] for x in v}
        out["kev"] = {
            "catalogVersion": kev.get("catalogVersion"),
            "stats": {
                "kevYesterday": sum(1 for x in v if x["dateAdded"] in yesterday_days),
                "kevWeek": sum(1 for x in v if today - dt.timedelta(days=7) <= D(x["dateAdded"]) < today),
                "kevDue7d": sum(1 for x in v if today <= D(x["dueDate"]) <= today + dt.timedelta(days=7)),
                "source": f"Catalogue CISA KEV v{kev.get('catalogVersion')} (cisagov/kev-data)",
            },
            "recent": sorted([x for x in v if D(x["dateAdded"]) >= today - dt.timedelta(days=7)], key=lambda x: x["dateAdded"], reverse=True),
            "due14": sorted([x for x in v if today <= D(x["dueDate"]) <= today + dt.timedelta(days=14)], key=lambda x: x["dueDate"]),
        }
    except Exception as e:
        kev_ids = set(); out["errors"].append(f"KEV : {e}")

    # --- CVE List
    try:
        d, newest, n = fetch_cvelist(a.work, since)
        recs = []
        for f in glob.glob(os.path.join(d, "cves", "*", "*", "CVE-*.json")):
            r = json.load(open(f))
            if r.get("cveMetadata", {}).get("state") != "PUBLISHED": continue
            if r["cveMetadata"].get("datePublished", "") < since: continue
            recs.append(summarize(r))
        def watched(s):
            t = (s["vendor"] + " " + s["product"]).lower()
            return any(w in t for w in WATCH)
        out["cves"] = {
            "listUpdated": newest, "fetched": n, "published_in_window": len(recs),
            "critical": sorted([s for s in recs if (s["cvss"] or 0) >= 9], key=lambda s: -(s["cvss"] or 0)),
            "watch": sorted([s for s in recs if watched(s) and (s["cvss"] or 0) >= 7], key=lambda s: -(s["cvss"] or 0)),
            "kev_in_window": [s for s in recs if s["cve"] in kev_ids],
        }
        for s in out["cves"]["critical"] + out["cves"]["watch"]:
            s["watchlist"] = watched(s)
    except Exception as e:
        out["errors"].append(f"CVE List : {e}")

    json.dump(out, open(a.out, "w"), ensure_ascii=False, indent=1)
    k = out.get("kev", {}).get("stats", {}); c = out.get("cves", {})
    print(f"KEV v{out.get('kev',{}).get('catalogVersion')} : hier={k.get('kevYesterday')} 7j={k.get('kevWeek')} échéances7j={k.get('kevDue7d')}")
    print(f"CVE List : {c.get('published_in_window')} publiées dans la fenêtre, {len(c.get('critical',[]))} critiques (>=9), {len(c.get('watch',[]))} sur la liste de surveillance (>=7)")
    for s in c.get("critical", []):
        print(f"  {s['cvss']:>4} {s['cve']:<17} {'*' if s['watchlist'] else ' '} {s['vendor']} | {s['product']} | {s['title'][:70]}")
    if out["errors"]: print("ERREURS :", out["errors"], file=sys.stderr)


if __name__ == "__main__":
    main()
