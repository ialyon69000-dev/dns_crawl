"""
Bruteforce de sous-domaines par dictionnaire
Utilise DnsResolver + ThreadPool
Gère wildcard detection pour éviter faux positifs
"""
from __future__ import annotations

import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Callable, Iterable

from .resolver import DnsResolver
from .utils import clean_domain_list

# Wordlist intégrée minimale (top 200)
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "test", "dev", "api", "app", "vpn", "secure",
    "blog", "shop", "store", "support", "help", "portal", "beta", "stage", "staging",
    "m", "mobile", "forum", "webmail", "email", "mx", "mx1", "mx2", "ns", "ns1", "ns2",
    "dns", "dns1", "dns2", "cdn", "static", "media", "img", "images", "assets",
    "login", "sso", "auth", "account", "accounts", "dashboard", "panel", "cpanel",
    "whm", "webdisk", "autodiscover", "autoconfig", "owa", "exchange", "lync",
    "sip", "jabber", "xmpp", "ldap", "db", "database", "sql", "mysql", "oracle",
    "pg", "postgres", "mongo", "redis", "cache", "memcached", "jenkins", "jira",
    "confluence", "gitlab", "github", "bitbucket", "ci", "cd", "build", "deploy",
    "staging", "preprod", "prod", "production", "demo", "sandbox", "test1", "test2",
    "old", "new", "v1", "v2", "v3", "api1", "api2", "rest", "graphql", "ws", "wss",
    "socket", "live", "stream", "video", "chat", "meet", "zoom", "teams",
    "docs", "documentation", "wiki", "kb", "knowledge", "helpdesk", "ticket",
    "status", "monitor", "monitoring", "grafana", "prometheus", "kibana", "elk",
    "log", "logs", "sentry", "analytics", "track", "stats", "metrics",
    "pay", "payment", "payments", "billing", "invoice", "checkout", "cart",
    "crm", "erp", "hr", "cms", "wp", "wordpress", "drupal", "joomla", "magento",
    "shopify", "cdn1", "cdn2", "origin", "edge", "cache1", "cache2",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "registry",
    "git", "svn", "hg", "repo", "artifactory", "nexus", "sonar",
    "vpn2", "remote", "access", "gateway", "proxy", "proxy1", "proxy2", "firewall",
    "gw", "fw", "router", "switch", "core", "edge1", "pop", "pop1",
    "smtp", "pop", "pop3", "imap", "imap4", "mail1", "mail2", "mx3",
    "newsletter", "marketing", "ads", "ad", "cdn-cgi", "well-known",
    "admin1", "administrator", "root", "super", "manage", "management",
    "control", "console", "internal", "private", "public", "external",
    "partner", "partners", "client", "clients", "customer", "customers",
    "user", "users", "account", "my", "myaccount", "profile", "id",
    "auth2", "oauth", "oauth2", "openid", "saml", "adfs", "ldap1",
    "files", "file", "upload", "uploads", "download", "downloads", "share",
    "backup", "bak", "old-site", "legacy", "archive", "temp", "tmp",
    "dev1", "dev2", "qa", "uat", "sit", "integration", "local", "localhost",
    "intranet", "extranet", "vpn1", "office", "corp", "enterprise",
]

def _load_wordlist_from_path(path: str | Path) -> list[str]:
    try:
        p = Path(path)
        if not p.exists():
            return []
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        cleaned = []
        for line in lines:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # Ne garder que le premier token (au cas où wordlist avec commentaires)
            line = line.split()[0]
            line = line.lstrip("*.").rstrip(".")
            if line:
                cleaned.append(line)
        return cleaned
    except Exception:
        return []

def get_wordlist(wordlist: Optional[str | list[str]] = None) -> list[str]:
    """
    Résout la wordlist à utiliser:
    - None -> DEFAULT_SUBDOMAINS
    - list[str] -> utiliser tel quel
    - str chemin fichier -> charger fichier
    - str "top100", "common", "large", "all" -> charger wordlists embarquées si présentes
    - str contient "," -> split en liste perso
    """
    if wordlist is None:
        return DEFAULT_SUBDOMAINS

    if isinstance(wordlist, list):
        return [w.strip().lower().lstrip("*.").rstrip(".") for w in wordlist if w.strip()]

    if isinstance(wordlist, str):
        wordlist = wordlist.strip()
        # Cas fichier
        if os.path.exists(wordlist):
            loaded = _load_wordlist_from_path(wordlist)
            if loaded:
                return loaded

        # Cas mot-clé embarqué
        lower = wordlist.lower()
        if lower in ("top100", "top100.txt"):
            return DEFAULT_SUBDOMAINS[:100]
        if lower in ("common", "common.txt", "top500"):
            # Charger depuis wordlists/ si présent
            p = Path(__file__).parent.parent / "wordlists" / "subdomains-common.txt"
            if p.exists():
                loaded = _load_wordlist_from_path(p)
                if loaded:
                    return loaded
            return DEFAULT_SUBDOMAINS
        if lower in ("large", "all", "large.txt", "huge"):
            p = Path(__file__).parent.parent / "wordlists" / "subdomains-large.txt"
            if p.exists():
                loaded = _load_wordlist_from_path(p)
                if loaded:
                    return loaded
            # fallback étendu: doubler avec préfixes
            extended = DEFAULT_SUBDOMAINS.copy()
            prefixes = ["eu", "us", "fr", "de", "uk", "api-", "web-", "app-", "svc-", "my-", "go-", "get-"]
            for pref in prefixes:
                for base in DEFAULT_SUBDOMAINS[:30]:
                    extended.append(f"{pref}{base}")
            return sorted(set(extended))

        # Cas liste inline "www,mail,api,admin"
        if "," in wordlist:
            parts = [p.strip().lower().lstrip("*.").rstrip(".") for p in wordlist.split(",")]
            return [p for p in parts if p]

        # Cas single word? -> traiter comme custom list d'un seul
        if wordlist and "." not in wordlist and "/" not in wordlist:
            # Peut-être l'utilisateur a passé directement "securite"
            # On le considère comme wordlist inline à un élément
            # Mais on préfère retourner default + ce mot
            # Non, on respecte: si c'est un path inexistant, on retourne [wordlist]
            # Pour éviter confusion, on check si ça ressemble à un fichier sans extension
            # On fait fallback sur défaut
            return DEFAULT_SUBDOMAINS

        return DEFAULT_SUBDOMAINS

    return DEFAULT_SUBDOMAINS


def bruteforce_subdomains(
    domain: str,
    wordlist: Optional[str | list[str]] = None,
    resolver: Optional[DnsResolver] = None,
    max_workers: int = 50,
    timeout: float = 3.0,
    verify_wildcard: bool = True,
    include_aaaa: bool = True,
    include_cname: bool = True,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> dict:
    """
    Bruteforce les sous-domaines d'un domaine avec une wordlist.

    Retourne dict:
      - found: list[dict] avec {subdomain, ips, cname, record_types}
      - tried: int
      - wildcard: bool
      - wildcard_ips: set[str]
      - duration: float
    """
    domain = domain.strip().lower().rstrip(".")
    res = resolver or DnsResolver(timeout=timeout)
    words = get_wordlist(wordlist)
    # Déduplication
    words = sorted(set(w.strip().lower() for w in words if w.strip()))

    start = time.time()

    # Détection wildcard
    is_wildcard = False
    wildcard_ips: set[str] = set()
    if verify_wildcard:
        is_wildcard = res.detect_wildcard(domain)
        if is_wildcard:
            wildcard_ips = res.get_wildcard_ips(domain)

    found: list[dict] = []
    tried = 0

    # Préparer les FQDN à tester
    fqdns = [f"{w}.{domain}" for w in words]

    # Pour progress
    total = len(fqdns)

    def _check_one(fqdn: str) -> Optional[dict]:
        # Résoudre A
        a_records = res.resolve(fqdn, "A")
        aaaa_records = res.resolve(fqdn, "AAAA") if include_aaaa else []
        cname_records = res.resolve(fqdn, "CNAME") if include_cname else []

        ips = a_records + aaaa_records

        # Si wildcard, filtrer les faux positifs qui matchent exactement les IPs wildcard
        if is_wildcard and ips:
            # Si toutes les IPs sont dans wildcard_ips et qu'il n'y a pas de CNAME distinct
            # on considère comme faux positif sauf si CNAME présent
            if set(ips).issubset(wildcard_ips) and not cname_records:
                # Vérifier aussi AAAA séparément
                # Si on a A/AAAA identiques au wildcard, c'est faux positif
                return None

        if ips or cname_records:
            # Au moins un enregistrement trouvé
            record_types = []
            if a_records:
                record_types.append("A")
            if aaaa_records:
                record_types.append("AAAA")
            if cname_records:
                record_types.append("CNAME")

            return {
                "subdomain": fqdn,
                "label": fqdn.split(".")[0],
                "ips": ips,
                "a": a_records,
                "aaaa": aaaa_records,
                "cname": cname_records,
                "record_types": record_types,
            }
        return None

    # Exécution parallèle
    batch_size = max_workers * 2
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Soumettre par batch pour éviter trop de futures d'un coup si liste énorme
        for i in range(0, len(fqdns), batch_size):
            batch = fqdns[i : i + batch_size]
            futures = {executor.submit(_check_one, fqdn): fqdn for fqdn in batch}
            for fut in as_completed(futures):
                tried += 1
                if progress_callback and tried % 50 == 0:
                    try:
                        progress_callback(tried, total)
                    except Exception:
                        pass
                result = fut.result()
                if result:
                    found.append(result)
            if progress_callback:
                try:
                    progress_callback(min(tried, total), total)
                except Exception:
                    pass

    duration = time.time() - start

    # Tri par subdomain
    found_sorted = sorted(found, key=lambda x: x["subdomain"])

    return {
        "domain": domain,
        "found": found_sorted,
        "found_domains": [f["subdomain"] for f in found_sorted],
        "tried": tried,
        "total_words": total,
        "wildcard": is_wildcard,
        "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
        "duration": duration,
        "success": len(found_sorted) > 0,
    }
