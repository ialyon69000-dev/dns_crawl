"""
Énumération des serveurs DNS d'une zone (ex: .ru, .fr, .com)

Deux niveaux:
 1. Énumérer les NS autoritaires d'un TLD lui-même (ex: dig NS ru → 6 serveurs)
 2. Énumérer TOUS les NS utilisés par TOUS les domaines d'une zone (ex: tous les NS qui hébergent des .ru)
    → nécessite une liste de domaines de la zone

Ce module fournit les outils pour le niveau 2, qui est le cas réel demandé:
"tous les serveurs DNS d'une zone .ru puis les crawler"

Sources pour obtenir la liste des domaines .ru:
  - crt.sh (CT logs) avec wildcard %.ru
  - Tranco top 1M filtré .ru
  - OpenINTEL, ViewDNS, Censys (nécessitent clé)
  - Fichier local (whois dump, zone file si accès)
  - CommonCrawl
"""
from __future__ import annotations

import time
import random
import json
import csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from collections import Counter

import requests

from .resolver import DnsResolver
from .utils import clean_domain_list


# ──────────────────────────────────────────────────────────────────────────────
# Niveau 1: NS du TLD lui-même (simple)
# ──────────────────────────────────────────────────────────────────────────────

def get_tld_nameservers(tld: str, resolver: Optional[DnsResolver] = None) -> dict:
    """
    Récupère les NS autoritaires du TLD lui-même.
    Ex: get_tld_nameservers("ru") → NS de .ru (a.dns.ripn.net, etc.)

    C'est la liste OFFICIELLE des serveurs qui gèrent .ru (env. 6-10).
    Utile pour comprendre l'infra du TLD, mais ce ne sont PAS tous les DNS
    hébergeant des domaines .ru (ça c'est niveau 2).
    """
    tld = tld.strip().lstrip(".").lower()
    res = resolver or DnsResolver()

    ns_hosts = res.get_ns(tld)
    # Alternative: query directement les root servers via NS type?
    # DnsResolver fait déjà ça.

    details: dict[str, dict] = {}
    for ns in ns_hosts:
        ips = res.resolve_ip(ns)
        details[ns] = {
            "hostname": ns,
            "ips": ips,
            "ptr": [res.reverse_lookup(ip) for ip in ips[:2]] if ips else [],
        }

    return {
        "tld": tld,
        "ns_count": len(ns_hosts),
        "ns_hosts": ns_hosts,
        "details": details,
        "success": len(ns_hosts) > 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Niveau 2: Tous les NS utilisés par les domaines d'une zone
# ──────────────────────────────────────────────────────────────────────────────

def fetch_domains_from_crtsh(
    tld: str,
    limit: Optional[int] = None,
    timeout: int = 20,
) -> dict:
    """
    Récupère tous les domaines d'un TLD via crt.sh (CT logs).
    Ex: tld="ru" → query "%.ru"

    ATTENTION: pour .ru, ça peut être MILLIONS. On limite par défaut.
    Utilise streaming / pagination implicite de crt.sh.
    """
    tld = tld.strip().lstrip(".").lower()
    query = f"%.{tld}"
    url = f"https://crt.sh/?q={query}&output=json"

    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "dns_crawl/zone_enum/1.0"})
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:300]}", "domains": [], "count": 0}
        data = resp.json()
        domains = set()
        for entry in data:
            name_value = entry.get("name_value", "") or entry.get("common_name", "")
            for line in name_value.split("\n"):
                line = line.strip().lower().rstrip(".").lstrip("*.").strip()
                if not line or "*" in line or "@" in line:
                    continue
                if line.endswith("." + tld) or line == tld:
                    domains.add(line)
        domains = clean_domain_list(list(domains))
        if limit:
            domains = domains[:limit]
        return {"success": True, "domains": domains, "count": len(domains), "source": "crt.sh", "query": query}
    except Exception as e:
        return {"success": False, "error": str(e), "domains": [], "count": 0}


def fetch_domains_from_tranco(
    tld: str,
    limit: Optional[int] = 10000,
    cache_path: Optional[str | Path] = None,
) -> dict:
    """
    Récupère les domaines .ru depuis Tranco top 1M (https://tranco-list.eu)
    Tranco publie une liste quotidienne ~1M domaines classés.
    On filtre pour ne garder que .ru.

    C'est un échantillon REPRESENTATIF mais non exhaustif (top sites).
    Pour exhaustif, il faut crt.sh ou zone file.
    """
    tld = tld.strip().lstrip(".").lower()
    # Tranco API: https://tranco-list.eu/download_daily?date=... (CSV)
    # Endpoint stable: https://tranco-list.eu/download/Q3W9X/1? ... mais change daily
    # Alternative simple: utiliser le dataset GitHub tranco/top-1m
    # Pour robustesse en sandbox, on tente plusieurs URLs
    urls = [
        "https://tranco-list.eu/top-1m.csv.zip",  # zip csv
        "https://tranco-list.eu/download_daily",
    ]
    domains: list[str] = []
    errors: list[str] = []

    for url in urls:
        try:
            resp = requests.get(url, timeout=15, headers={"User-Agent": "dns_crawl/zone_enum/1.0"})
            if resp.status_code == 200:
                text = resp.text[:5_000_000]  # limiter
                for line in text.splitlines():
                    # Format: rank,domain  ou juste domain
                    parts = line.strip().split(",")
                    candidate = parts[-1].strip().lower().rstrip(".") if parts else ""
                    if candidate.endswith("." + tld) and "." in candidate:
                        domains.append(candidate)
                        if limit and len(domains) >= limit:
                            break
                if domains:
                    # Dédupliquer
                    domains = clean_domain_list(domains)
                    return {"success": True, "domains": domains, "count": len(domains), "source": "tranco", "url": url}
            errors.append(f"{url}: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"{url}: {e}")
            continue

    return {"success": False, "error": "; ".join(errors), "domains": [], "count": 0, "source": "tranco"}


def load_domains_from_file(path: str | Path, tld: Optional[str] = None) -> dict:
    """Charge une liste de domaines depuis un fichier txt/csv/json (un domaine par ligne)"""
    p = Path(path)
    if not p.exists():
        return {"success": False, "error": f"Fichier introuvable: {path}", "domains": [], "count": 0}
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
        domains: list[str] = []
        # Détecter format JSON
        if text.strip().startswith("[") or text.strip().startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    candidates = data
                elif isinstance(data, dict) and "domains" in data:
                    candidates = data["domains"]
                else:
                    candidates = []
                for c in candidates:
                    if isinstance(c, str):
                        domains.append(c.strip().lower().rstrip("."))
                    elif isinstance(c, dict) and "domain" in c:
                        domains.append(str(c["domain"]).strip().lower().rstrip("."))
            except Exception:
                # Fallback ligne par ligne
                pass
        # CSV / TXT ligne par ligne
        if not domains:
            for line in text.splitlines():
                line = line.strip().lower().rstrip(".")
                if not line or line.startswith("#"):
                    continue
                # Première colonne si CSV
                if "," in line:
                    line = line.split(",")[0].strip()
                if line:
                    domains.append(line)

        # Filtrer par TLD si demandé
        if tld:
            tld = tld.strip().lstrip(".").lower()
            domains = [d for d in domains if d.endswith("." + tld) or d == tld]

        domains = clean_domain_list(domains)
        return {"success": True, "domains": domains, "count": len(domains), "source": str(p)}
    except Exception as e:
        return {"success": False, "error": str(e), "domains": [], "count": 0}


# ──────────────────────────────────────────────────────────────────────────────
# Énumération NS à partir d'une liste de domaines
# ──────────────────────────────────────────────────────────────────────────────

def enumerate_ns_for_domains(
    domains: list[str],
    max_workers: int = 80,
    resolver: Optional[DnsResolver] = None,
    timeout: float = 2.5,
    show_progress: bool = False,
) -> dict:
    """
    Pour chaque domaine de la liste, résout ses NS autoritaires.
    Retourne:
      - mapping domaine -> [ns]
      - compteur global des NS (les plus utilisés)
      - liste dédupliquée de tous les NS
    """
    res = resolver or DnsResolver(timeout=timeout)
    total = len(domains)
    mapping: dict[str, list[str]] = {}
    counter: Counter = Counter()
    errors = 0

    def _get_ns_one(domain: str) -> tuple[str, list[str]]:
        try:
            ns = res.get_ns(domain)
            return domain, ns
        except Exception:
            return domain, []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_get_ns_one, d): d for d in domains}
        done = 0
        for fut in as_completed(futures):
            domain, ns_list = fut.result()
            done += 1
            if ns_list:
                mapping[domain] = ns_list
                for ns in ns_list:
                    counter[ns] += 1
            else:
                errors += 1
            if show_progress and done % 500 == 0:
                print(f"  [{done}/{total}] NS uniques: {len(counter)} (ex: {', '.join(list(counter.most_common(2)))} )")

    # Tri par popularité
    most_common = counter.most_common()
    all_ns_sorted = [ns for ns, cnt in most_common]

    return {
        "success": len(mapping) > 0,
        "tld_or_zone": None,  # rempli par appelant
        "domains_processed": total,
        "domains_with_ns": len(mapping),
        "domains_without_ns": errors,
        "mapping": mapping,  # domaine -> [ns]
        "ns_counter": dict(most_common),
        "ns_list": all_ns_sorted,
        "ns_count": len(all_ns_sorted),
        "top_ns": most_common[:20],
        "counter": counter,
    }


def crawl_ns_zone(
    tld: str,
    domains: Optional[list[str]] = None,
    input_file: Optional[str | Path] = None,
    limit: Optional[int] = None,
    max_workers: int = 80,
    resolver: Optional[DnsResolver] = None,
    sources: list[str] = None,
) -> dict:
    """
    Orchestre l'énumération complète des NS d'une zone.

    tld: ex "ru", ".ru"
    domains: liste directe (prioritaire)
    input_file: fichier avec domaines (si domains vide)
    limit: limiter le nombre de domaines à traiter (pour test)
    sources: ["crt.sh", "tranco"] si on doit fetch

    Retourne dict complet avec stats pour ensuite crawler chaque NS.
    """
    tld = tld.strip().lstrip(".").lower()
    res = resolver or DnsResolver()
    t_start = time.time()

    # 1. Obtenir liste domaines
    fetch_result: Optional[dict] = None
    if domains and len(domains) > 0:
        all_domains = clean_domain_list(domains)
        fetch_result = {"success": True, "domains": all_domains, "count": len(all_domains), "source": "provided"}
    elif input_file:
        fetch_result = load_domains_from_file(input_file, tld=tld)
        all_domains = fetch_result.get("domains", [])
    else:
        # Auto-fetch via sources
        sources = sources or ["crt.sh"]
        all_domains = []
        for src in sources:
            if src in ("crt.sh", "crt", "ct"):
                fetch_result = fetch_domains_from_crtsh(tld, limit=limit)
                if fetch_result.get("success"):
                    all_domains = fetch_result["domains"]
                    break
            elif src in ("tranco", "top1m"):
                fetch_result = fetch_domains_from_tranco(tld, limit=limit or 10000)
                if fetch_result.get("success"):
                    all_domains = fetch_result["domains"]
                    break
        if not all_domains:
            return {
                "success": False,
                "error": f"Impossible de récupérer domaines pour .{tld} via {sources}: {fetch_result.get('error') if fetch_result else 'no source'}",
                "tld": tld,
            }

    if limit and len(all_domains) > limit:
        all_domains = all_domains[:limit]

    # 2. Énumérer NS
    enum = enumerate_ns_for_domains(all_domains, max_workers=max_workers, resolver=res)
    enum["tld_or_zone"] = tld
    enum["fetch_result"] = fetch_result
    enum["duration_fetch"] = time.time() - t_start

    # 3. Détails enrichis pour chaque NS (IPs, etc.)
    ns_details: dict[str, dict] = {}
    for ns in enum["ns_list"][:100]:  # limiter détails aux top 100 pour ne pas trop query
        ips = res.resolve_ip(ns)
        ns_details[ns] = {
            "hostname": ns,
            "count": enum["ns_counter"][ns],
            "percent": round(100 * enum["ns_counter"][ns] / enum["domains_with_ns"], 2) if enum["domains_with_ns"] else 0,
            "ips": ips,
        }

    # 4. Infos TLD lui-même
    tld_ns = get_tld_nameservers(tld, resolver=res)

    duration = time.time() - t_start

    return {
        "success": True,
        "tld": tld,
        "tld_ns": tld_ns,
        "domains_total": len(all_domains),
        "domains_source": fetch_result.get("source") if fetch_result else "unknown",
        "ns_enumeration": enum,
        "ns_details": ns_details,
        "duration": duration,
        "summary": f"Zone .{tld}: {len(all_domains)} domaines → {enum['ns_count']} NS uniques (top: {', '.join([n for n,_ in enum['top_ns'][:3]])})",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Crawler des NS trouvés (les crawler un par un avec DnsCrawler)
# ──────────────────────────────────────────────────────────────────────────────

def crawl_all_ns(
    ns_list: list[str],
    max_workers: int = 10,
    crawler_config: Optional[dict] = None,
    limit_ns: Optional[int] = None,
) -> dict:
    """
    Crawl chaque NS (reverse) pour obtenir tous les sites dessus.
    Utilise DnsCrawler en mode --reverse.
    ATTENTION: très lourd si ns_list grand (milliers). Limiter ou faire par batch.
    """
    from .crawler import DnsCrawler, CrawlConfig

    if limit_ns:
        ns_list = ns_list[:limit_ns]

    config = CrawlConfig(
        do_resolve_all=True,
        do_zone_transfer=False,
        do_ct_logs=False,
        do_bruteforce=False,
        do_reverse_ip=True,
        do_web_check=False,
        **(crawler_config or {}),
    )
    crawler = DnsCrawler(config=config)

    results: dict[str, dict] = {}
    errors: list[str] = []

    def _crawl_one(ns: str):
        try:
            r = crawler.crawl(ns)
            return ns, {"success": True, "count": r.count, "domains": r.all_domains[:50], "duration": r.duration, "result": r.to_dict()}
        except Exception as e:
            return ns, {"success": False, "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_crawl_one, ns): ns for ns in ns_list}
        for fut in as_completed(futures):
            ns, data = fut.result()
            results[ns] = data
            if not data.get("success"):
                errors.append(f"{ns}: {data.get('error')}")

    total_domains = set()
    for v in results.values():
        if v.get("domains"):
            total_domains.update(v["domains"])

    return {
        "success": True,
        "ns_crawled": len(results),
        "ns_list": ns_list,
        "per_ns": results,
        "total_unique_domains_across_all_ns": len(total_domains),
        "errors": errors,
    }
