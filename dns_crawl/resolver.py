"""
Résolveur DNS robuste basé sur dnspython
Gère: NS discovery, multi-resolvers, fallback, timeout, cache
"""
from __future__ import annotations

import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import dns.resolver
import dns.rdatatype
import dns.exception
import dns.name
import dns.message
import dns.query
import dns.zone
import dns.reversename

DEFAULT_RESOLVERS = [
    "8.8.8.8",        # Google - fiable dans cet environnement
    "8.8.4.4",
    "1.1.1.1",        # Cloudflare
    "1.0.0.1",
    "9.9.9.9",        # Quad9
    "208.67.222.222", # OpenDNS
]

COMMON_RECORDS = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]


class DnsResolver:
    """
    Wrapper autour de dns.resolver.Resolver avec:
    - Plusieurs résolveurs (rotation / fallback)
    - Timeout configurable
    - Cache mémoire
    - Méthodes haut niveau (resolve, resolve_all_types, get_ns, etc.)
    """

    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        timeout: float = 3.0,
        lifetime: float = 5.0,
        use_system_resolvers: bool = False,
        enable_cache: bool = True,
    ):
        self.timeout = timeout
        self.lifetime = lifetime
        self.enable_cache = enable_cache
        self._cache: dict[tuple[str, str], list[str]] = {}

        self.resolver = dns.resolver.Resolver(configure=use_system_resolvers)
        if not use_system_resolvers:
            self.resolver.nameservers = nameservers or DEFAULT_RESOLVERS
        elif nameservers:
            self.resolver.nameservers = nameservers

        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        # Tentatives
        self.resolver.retry_servfail = True

    def _cache_get(self, domain: str, rdtype: str) -> Optional[list[str]]:
        if not self.enable_cache:
            return None
        return self._cache.get((domain.lower(), rdtype.upper()))

    def _cache_set(self, domain: str, rdtype: str, values: list[str]):
        if self.enable_cache:
            self._cache[(domain.lower(), rdtype.upper())] = values

    def resolve(self, domain: str, rdtype: str = "A", raise_on_error: bool = False) -> list[str]:
        """
        Résout un type d'enregistrement pour un domaine.
        Retourne liste de strings (vide si NXDOMAIN / NoAnswer / Timeout)
        """
        domain = domain.strip().rstrip(".")
        rdtype = rdtype.upper()

        cached = self._cache_get(domain, rdtype)
        if cached is not None:
            return cached

        try:
            answers = self.resolver.resolve(domain, rdtype)
            result = []
            for rdata in answers:
                # Gérer chaque type proprement
                try:
                    text = rdata.to_text().strip('"').strip("'")
                    # Pour MX: "10 mail.example.com." -> garder host
                    # Pour SOA, SRV etc: garder brut
                    result.append(text)
                except Exception:
                    result.append(str(rdata))
            self._cache_set(domain, rdtype, result)
            return result

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            self._cache_set(domain, rdtype, [])
            if raise_on_error:
                raise
            return []
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
            if raise_on_error:
                raise
            return []
        except Exception:
            if raise_on_error:
                raise
            return []

    def resolve_all(self, domain: str, types: Optional[list[str]] = None) -> dict[str, list[str]]:
        """Résout tous les types courants pour un domaine"""
        types = types or COMMON_RECORDS
        results: dict[str, list[str]] = {}
        for t in types:
            vals = self.resolve(domain, t)
            if vals:
                results[t] = vals
        return results

    def get_ns(self, domain: str) -> list[str]:
        """Récupère les NS autoritaires du domaine (via NS record + fallback SOA)"""
        ns_records = self.resolve(domain, "NS")
        if ns_records:
            return [n.rstrip(".") for n in ns_records]

        # Fallback: SOA MNAME
        soa = self.resolve(domain, "SOA")
        if soa:
            # SOA format: "ns1.example.com. hostmaster.example.com. 2020010101 ..."
            first = soa[0].split()[0] if soa[0] else ""
            if first:
                return [first.rstrip(".")]
        return []

    def get_mx(self, domain: str) -> list[str]:
        return self.resolve(domain, "MX")

    def get_txt(self, domain: str) -> list[str]:
        return self.resolve(domain, "TXT")

    def get_a(self, domain: str) -> list[str]:
        return self.resolve(domain, "A")

    def get_aaaa(self, domain: str) -> list[str]:
        return self.resolve(domain, "AAAA")

    def get_soa(self, domain: str) -> list[str]:
        return self.resolve(domain, "SOA")

    def get_cname(self, domain: str) -> list[str]:
        return self.resolve(domain, "CNAME")

    def resolve_ip(self, domain: str) -> list[str]:
        """Récupère A + AAAA"""
        ips = []
        ips.extend(self.resolve(domain, "A"))
        ips.extend(self.resolve(domain, "AAAA"))
        return ips

    def reverse_lookup(self, ip: str) -> list[str]:
        """PTR lookup pour une IP"""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []

    def exists(self, domain: str, rdtype: str = "A") -> bool:
        """Vérifie si un enregistrement existe (utile pour bruteforce)"""
        vals = self.resolve(domain, rdtype)
        if vals:
            return True
        # Vérifier aussi AAAA si A demandé et vice versa pour wildcard detection
        return False

    def detect_wildcard(self, domain: str) -> bool:
        """
        Détecte si le domaine a un wildcard DNS (*.example.com)
        Teste 2 sous-domaines aléatoires impossibles
        """
        rand1 = f"dns-crawl-wildcard-test-{random.randint(1000000, 9999999)}.{domain}"
        rand2 = f"dns-crawl-wildcard-test-{random.randint(1000000, 9999999)}.{domain}"
        ips1 = set(self.resolve(rand1, "A"))
        ips2 = set(self.resolve(rand2, "A"))

        # Si les deux aléatoires résolvent vers même IP => wildcard probable
        if ips1 and ips2 and ips1 == ips2:
            return True
        # Si au moins un résout, suspect mais pas conclusif
        # On considère wildcard seulement si les deux résolvent identique
        return False

    def get_wildcard_ips(self, domain: str) -> set[str]:
        """Retourne les IPs du wildcard si présent"""
        rand = f"dns-crawl-wildcard-{random.randint(1000000,9999999)}.{domain}"
        return set(self.resolve(rand, "A")) | set(self.resolve(rand, "AAAA"))

    def bulk_resolve(
        self,
        domains: list[str],
        rdtype: str = "A",
        max_workers: int = 50,
        show_progress: bool = False,
    ) -> dict[str, list[str]]:
        """
        Résolution en masse avec threads.
        Retourne dict domaine -> [values]
        """
        results: dict[str, list[str]] = {}

        def _resolve_one(d: str):
            vals = self.resolve(d, rdtype)
            return d, vals

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_resolve_one, d): d for d in domains}
            for fut in as_completed(futures):
                d, vals = fut.result()
                if vals:
                    results[d] = vals
        return results

    def get_authoritative_ns_ips(self, domain: str) -> dict[str, list[str]]:
        """
        Résout les IPs des NS autoritaires.
        Retourne {ns_host: [ips]}
        """
        ns_hosts = self.get_ns(domain)
        out: dict[str, list[str]] = {}
        for ns in ns_hosts:
            ips = self.resolve_ip(ns)
            out[ns] = ips
        return out
