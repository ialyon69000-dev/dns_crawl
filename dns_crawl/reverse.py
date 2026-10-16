"""
Reverse DNS et Reverse IP lookup
- PTR pour IP / CIDR
- Reverse IP via services OSINT (hackertarget, viewdns, rapiddns...)
"""
from __future__ import annotations

import ipaddress
import re
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
import dns.reversename
import dns.resolver

from .resolver import DnsResolver
from .utils import clean_domain_list

# --- PTR classique ---

def reverse_ptr_range(
    target: str,
    resolver: Optional[DnsResolver] = None,
    max_workers: int = 50,
    max_hosts: int = 2048,
) -> dict:
    """
    Fait un PTR lookup sur une IP unique ou un CIDR.
    Limite max_hosts pour éviter explosion (ex: /16 = 65536)
    """
    res = resolver or DnsResolver()
    ips: list[str] = []

    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            # Limiter
            num = net.num_addresses
            if num > max_hosts:
                # Prendre seulement les premiers max_hosts
                # pour éviter scan massif trop long
                ips = [str(ip) for ip in list(net.hosts())[:max_hosts]]
                truncated = True
            else:
                ips = [str(ip) for ip in net.hosts()]
                truncated = num > max_hosts
                # Pour /32, hosts() vide, donc prendre l'IP elle-même
                if not ips:
                    ips = [str(net.network_address)]
                    truncated = False
        else:
            # IP unique
            ipaddress.ip_address(target)  # validation
            ips = [target]
            truncated = False
    except ValueError as e:
        return {
            "success": False,
            "error": f"IP/CIDR invalide: {e}",
            "target": target,
            "results": [],
            "ips_scanned": 0,
        }

    results: list[dict] = []

    def _ptr_one(ip: str) -> Optional[dict]:
        try:
            rev_name = dns.reversename.from_address(ip)
            try:
                answers = res.resolver.resolve(rev_name, "PTR")
                hostnames = [str(r).rstrip(".") for r in answers]
                if hostnames:
                    return {"ip": ip, "ptr": hostnames}
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                return None
            except Exception:
                return None
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ptr_one, ip): ip for ip in ips}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    # Trier par IP
    results_sorted = sorted(results, key=lambda x: ipaddress.ip_address(x["ip"]))

    all_hostnames = []
    for r in results_sorted:
        all_hostnames.extend(r["ptr"])
    all_hostnames = clean_domain_list(all_hostnames)

    return {
        "success": len(results_sorted) > 0,
        "target": target,
        "results": results_sorted,
        "domains": all_hostnames,
        "count": len(results_sorted),
        "ips_scanned": len(ips),
        "truncated": truncated if "/" in target else False,
        "max_hosts": max_hosts,
    }


# --- Reverse IP via OSINT (sites sur même IP) ---

USER_AGENT = "dns_crawl/1.0 (OSINT reverse-ip)"

def _query_hackertarget(ip: str, timeout: int = 10) -> list[str]:
    """
    https://api.hackertarget.com/reverseiplookup/?q=1.1.1.1
    Retourne liste de domaines ou [] si erreur / not found
    Gratuit mais rate limité
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        text = resp.text.strip()
        if not text:
            return []
        # Réponses d'erreur connues
        lower = text.lower()
        if "error" in lower and ("limit" in lower or "exceeded" in lower or "invalid" in lower):
            return []
        if "no records" in lower or "no result" in lower:
            return []
        # Normalement liste un domaine par ligne, parfois avec virgules
        domains = []
        for line in text.splitlines():
            line = line.strip().lower().rstrip(".")
            if not line:
                continue
            # Hackertarget peut renvoyer CSV "domain,ip" selon endpoint?
            # Pour reverseiplookup c'est juste domaines
            # Nettoyer
            if "," in line:
                # Prendre le premier champ
                line = line.split(",")[0].strip()
            if "." in line and " " not in line:
                domains.append(line)
        return clean_domain_list(domains)
    except Exception:
        return []

def _query_rapiddns(ip_or_ns: str, timeout: int = 12) -> list[str]:
    """
    Rapiddns.io a deux endpoints:
    - https://rapiddns.io/sameip/1.1.1.1?full=1#result  (même IP)
    - https://rapiddns.io/samedns/ns1.example.com?full=1#result (même NS)

    On scape le HTML / JSON embarqué. Le site renvoie une table HTML.
    On tente de parser les domaines via regex.
    """
    domains: list[str] = []
    # Le site a une API JSON non documentée parfois: https://rapiddns.io/sameip/1.1.1.1?full=1&json=1
    # Testons d'abord la version HTML simple
    urls_to_try = [
        f"https://rapiddns.io/sameip/{ip_or_ns}?full=1#result",
        f"https://rapiddns.io/samedns/{ip_or_ns}?full=1#result",
        f"https://rapiddns.io/sameip/{ip_or_ns}?full=1",
        f"https://rapiddns.io/samedns/{ip_or_ns}?full=1",
    ]
    # Déterminer si c'est IP ou NS pour prioriser
    is_ip = False
    try:
        ipaddress.ip_address(ip_or_ns)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        urls_to_try = urls_to_try[0:1] + urls_to_try[2:3]  # sameip seulement
    else:
        urls_to_try = urls_to_try[1:2] + urls_to_try[3:4]  # samedns seulement

    for url in urls_to_try:
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
            if resp.status_code != 200:
                continue
            html = resp.text
            # Chercher les domaines dans la table: <td><a href="...">domain</a></td> ou similar
            # Rapiddns met les domaines dans des <td> avec souvent le domaine brut
            # Utiliser regex simple pour extraire domaines
            # Ex: <td>example.com</td> ou >example.com</a>
            # On utilise une regex domaine générale et on filtre
            # Extraire tous les candidats domaine-like du HTML
            candidates = re.findall(r'>([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,60}\.[a-zA-Z]{2,})<', html)
            # Aussi href="/domain/example.com"
            candidates += re.findall(r'/domain/([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,60}\.[a-zA-Z]{2,})', html)
            # Filtrer bruits (rapiddns.io, etc.)
            filtered = []
            for c in candidates:
                c = c.lower().rstrip(".")
                if c in ("rapiddns.io", "example.com", "www.rapiddns.io"):
                    continue
                if "rapiddns" in c:
                    continue
                if "." not in c:
                    continue
                # Exclure les IPs
                try:
                    ipaddress.ip_address(c)
                    continue
                except ValueError:
                    pass
                filtered.append(c)
            if filtered:
                domains.extend(filtered)
                break  # succès, pas besoin d'essayer autre URL
        except Exception:
            continue
        time.sleep(0.5)

    return clean_domain_list(domains)

def _query_viewdns(ip_or_ns: str, timeout: int = 12) -> list[str]:
    """
    ViewDNS.info reverse IP: https://viewdns.info/reverseip/?host=1.1.1.1&t=1
    Et reverse NS: https://viewdns.info/reversedns/?host=ns1.example.com
    HTML à parser, similaire à rapiddns.
    On tente mais c'est souvent bloqué sans JS.
    """
    # On tente le reverse IP
    urls = [
        f"https://viewdns.info/reverseip/?host={ip_or_ns}&t=1",
        f"https://viewdns.info/reversedns/?host={ip_or_ns}",
    ]
    domains: list[str] = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if resp.status_code != 200:
                continue
            html = resp.text
            candidates = re.findall(r'>([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,60}\.[a-zA-Z]{2,})<', html)
            filtered = []
            for c in candidates:
                c = c.lower().rstrip(".")
                if "viewdns" in c:
                    continue
                if "." not in c:
                    continue
                try:
                    ipaddress.ip_address(c)
                    continue
                except ValueError:
                    pass
                filtered.append(c)
            if filtered:
                domains.extend(filtered)
                break
        except Exception:
            continue
    return clean_domain_list(domains)


def reverse_ip_lookup(
    target: str,
    sources: Optional[list[str]] = None,
    timeout: int = 10,
    resolver: Optional[DnsResolver] = None,
) -> dict:
    """
    Lookup reverse IP / reverse NS via OSINT.
    target: IP ou NS hostname ou domaine
    sources: liste parmi ["hackertarget", "rapiddns", "viewdns", "ptr"]  (ptr = PTR local)
    Retourne dict:
      - success: bool
      - domains: list[str] (tous les domaines trouvés)
      - by_source: dict[source -> list[str]]
      - target: str
      - resolved_ips: list[str] si target était domaine/NS
    """
    sources = sources or ["ptr", "hackertarget", "rapiddns"]
    target = target.strip().rstrip(".")

    resolved_ips: list[str] = []
    # Si target est domaine/NS, résoudre son IP pour les lookups IP-based
    if not _is_ip(target):
        res = resolver or DnsResolver()
        resolved_ips = res.resolve_ip(target)
    else:
        resolved_ips = [target]

    by_source: dict[str, list[str]] = {}
    all_domains: set[str] = set()

    # Pour chaque source, interroger
    for src in sources:
        domains: list[str] = []
        try:
            if src == "ptr":
                # PTR direct sur IPs résolues
                if resolved_ips:
                    for ip in resolved_ips:
                        ptr_res = reverse_ptr_range(ip, resolver=resolver, max_workers=20)
                        if ptr_res.get("domains"):
                            domains.extend(ptr_res["domains"])
                else:
                    # Si c'était déjà IP
                    ptr_res = reverse_ptr_range(target, resolver=resolver, max_workers=20)
                    if ptr_res.get("domains"):
                        domains.extend(ptr_res["domains"])

            elif src == "hackertarget":
                # Hackertarget fonctionne par IP
                for ip in resolved_ips[:3]:  # limiter à 3 IPs max (éviter rate limit)
                    found = _query_hackertarget(ip, timeout=timeout)
                    if found:
                        domains.extend(found)
                    time.sleep(0.8)  # être gentil

            elif src == "rapiddns":
                # Rapiddns peut prendre IP ou NS hostname directement
                # Essayer target original puis IPs
                candidates = [target] + resolved_ips[:2]
                for cand in candidates:
                    found = _query_rapiddns(cand, timeout=timeout)
                    if found:
                        domains.extend(found)
                        break  # succès, pas besoin autres
                    time.sleep(0.5)

            elif src == "viewdns":
                candidates = [target] + resolved_ips[:2]
                for cand in candidates:
                    found = _query_viewdns(cand, timeout=timeout)
                    if found:
                        domains.extend(found)
                        break
                    time.sleep(0.5)
            else:
                continue

            domains = clean_domain_list(domains)
            by_source[src] = domains
            all_domains.update(domains)

        except Exception as e:
            by_source[src] = []
            # On ne fail pas global

        # Pause entre sources
        time.sleep(0.3)

    all_sorted = sorted(all_domains)

    return {
        "success": len(all_sorted) > 0,
        "target": target,
        "domains": all_sorted,
        "count": len(all_sorted),
        "by_source": by_source,
        "resolved_ips": resolved_ips,
        "sources_used": sources,
    }


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
