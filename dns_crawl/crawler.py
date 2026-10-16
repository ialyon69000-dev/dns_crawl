"""
Orchestrateur principal : DnsCrawler
Combine toutes les techniques pour répondre à :
"Toutes les sites webs référencés dessus" (sur un DNS / domaine / IP / NS)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal

from .resolver import DnsResolver
from .zone_transfer import attempt_zone_transfer
from .ct_logs import query_crtsh
from .bruteforce import bruteforce_subdomains, get_wordlist
from .reverse import reverse_ptr_range, reverse_ip_lookup
from .web_check import bulk_check
from .utils import clean_domain_list, detect_target_type, normalize_target

@dataclass
class CrawlConfig:
    """
    Configuration du crawl
    """
    # Techniques à activer
    do_resolve_all: bool = True          # Résoudre A, MX, NS, TXT, etc. sur domaine principal
    do_zone_transfer: bool = True        # Tenter AXFR
    do_ct_logs: bool = True              # Certificate Transparency (crt.sh)
    do_bruteforce: bool = True           # Bruteforce dictionnaire
    do_reverse_ip: bool = False          # Reverse IP (OSINT) - désactivé par défaut car peut être lent/rate limité
    do_web_check: bool = False           # Vérifier HTTP

    # Params bruteforce
    wordlist: Optional[str | list[str]] = None  # None = default top ~200
    bruteforce_workers: int = 50
    bruteforce_timeout: float = 3.0

    # Params généraux
    resolvers: Optional[list[str]] = None  # Custom DNS servers
    dns_timeout: float = 3.0
    ct_timeout: int = 15

    # Reverse IP sources
    reverse_sources: list[str] = field(default_factory=lambda: ["hackertarget", "rapiddns", "ptr"])

    # Web check
    web_check_workers: int = 20
    web_check_timeout: int = 5

    # Sortie
    verbose: bool = False

@dataclass
class CrawlResult:
    target: str
    target_type: str  # domain, ns, ip, cidr, unknown
    normalized: str
    started_at: float
    finished_at: float = 0
    duration: float = 0

    # Enregistrements DNS du domaine principal
    dns_records: dict = field(default_factory=dict)
    ns_hosts: list[str] = field(default_factory=list)
    ns_ips: dict = field(default_factory=dict)

    # Zone transfer
    zone_transfer: Optional[dict] = None

    # CT logs
    ct_logs: Optional[dict] = None

    # Bruteforce
    bruteforce: Optional[dict] = None

    # Reverse
    reverse_ptr: Optional[dict] = None
    reverse_ip: Optional[dict] = None

    # Web check
    web_checks: Optional[dict] = None

    # Synthèse finale: TOUS les domaines/sites trouvés (dédupliqués)
    all_domains: list[str] = field(default_factory=list)
    all_websites: list[str] = field(default_factory=list)  # URLs https://

    # Erreurs / infos
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def count(self) -> int:
        return len(self.all_domains)

    def summary(self) -> str:
        lines = [
            f"Cible: {self.target} ({self.target_type}) -> {self.normalized}",
            f"Durée: {self.duration:.2f}s",
            f"Sources: {', '.join(self.sources_used) or 'aucune'}",
            f"Total domaines/sites uniques: {self.count}",
        ]
        if self.dns_records:
            lines.append(f"Records DNS: {list(self.dns_records.keys())}")
        if self.zone_transfer:
            lines.append(f"Zone transfer: {'SUCCÈS' if self.zone_transfer['success'] else 'échoué'} ({self.zone_transfer['count']} records)")
        if self.ct_logs:
            lines.append(f"CT logs (crt.sh): {len(self.ct_logs.get('domains', []))} domaines")
        if self.bruteforce:
            lines.append(f"Bruteforce: {len(self.bruteforce.get('found_domains', []))} trouvés / {self.bruteforce.get('tried')} testés (wildcard={self.bruteforce.get('wildcard')})")
        if self.reverse_ip:
            lines.append(f"Reverse IP: {self.reverse_ip.get('count',0)} domaines (IPs {self.reverse_ip.get('resolved_ips')})")
        if self.reverse_ptr:
            lines.append(f"Reverse PTR: {self.reverse_ptr.get('count',0)} entrées ({self.reverse_ptr.get('ips_scanned',0)} IPs scannées)")
        if self.web_checks:
            alive = sum(1 for v in self.web_checks.values() if v.get("alive"))
            lines.append(f"Web check: {alive}/{len(self.web_checks)} vivants")
        if self.errors:
            lines.append(f"Erreurs: {self.errors[:3]}")
        return "\n".join(lines)


class DnsCrawler:
    """
    Crawler DNS principal.
    Détecte automatiquement le type de cible et lance les techniques adaptées.
    """

    def __init__(self, config: Optional[CrawlConfig] = None):
        self.config = config or CrawlConfig()
        self.resolver = DnsResolver(
            nameservers=self.config.resolvers,
            timeout=self.config.dns_timeout,
        )

    def crawl(self, target: str) -> CrawlResult:
        target = target.strip()
        normalized = normalize_target(target)
        target_type = detect_target_type(normalized)

        started = time.time()
        result = CrawlResult(
            target=target,
            target_type=target_type,
            normalized=normalized,
            started_at=started,
        )

        # Collecteur global de domaines
        all_found: set[str] = set()

        # Toujours ajouter la cible elle-même si c'est un domaine
        if target_type in ("domain", "ns"):
            all_found.add(normalized)

        # --- Cas IP / CIDR : reverse uniquement ---
        if target_type in ("ip", "cidr"):
            if self.config.do_reverse_ip or True:  # Toujours faire reverse pour IP
                # PTR range
                try:
                    ptr_res = reverse_ptr_range(normalized, resolver=self.resolver)
                    result.reverse_ptr = ptr_res
                    result.sources_used.append("reverse_ptr")
                    if ptr_res.get("domains"):
                        all_found.update(ptr_res["domains"])
                except Exception as e:
                    result.errors.append(f"PTR error: {e}")

                # Reverse IP OSINT
                if self.config.do_reverse_ip:
                    try:
                        rev_ip = reverse_ip_lookup(normalized, sources=self.config.reverse_sources, resolver=self.resolver)
                        result.reverse_ip = rev_ip
                        result.sources_used.append("reverse_ip")
                        if rev_ip.get("domains"):
                            all_found.update(rev_ip["domains"])
                    except Exception as e:
                        result.errors.append(f"Reverse IP error: {e}")
            else:
                # Même sans do_reverse_ip, on fait PTR
                try:
                    ptr_res = reverse_ptr_range(normalized, resolver=self.resolver)
                    result.reverse_ptr = ptr_res
                    result.sources_used.append("reverse_ptr")
                    if ptr_res.get("domains"):
                        all_found.update(ptr_res["domains"])
                except Exception as e:
                    result.errors.append(f"PTR error: {e}")

            # Optionnel: web check sur domaines trouvés
            if self.config.do_web_check and all_found:
                try:
                    wc = bulk_check(list(all_found), max_workers=self.config.web_check_workers, timeout=self.config.web_check_timeout)
                    result.web_checks = wc
                    result.sources_used.append("web_check")
                except Exception as e:
                    result.errors.append(f"Web check error: {e}")

            result.all_domains = clean_domain_list(list(all_found))
            result.all_websites = [f"https://{d}" for d in result.all_domains]
            result.finished_at = time.time()
            result.duration = result.finished_at - started
            return result

        # --- Cas Domaine / NS ---
        # 1. DNS records principaux
        if self.config.do_resolve_all:
            try:
                records = self.resolver.resolve_all(normalized)
                result.dns_records = records
                result.ns_hosts = self.resolver.get_ns(normalized)
                result.ns_ips = self.resolver.get_authoritative_ns_ips(normalized)
                result.sources_used.append("dns_records")
                # Ajouter les NS, MX hostnames comme domaines trouvés
                for vals in records.values():
                    for v in vals:
                        # Extraire hostnames des enregistrements
                        # MX: "10 mail.example.com." -> prendre dernier token
                        tokens = v.split()
                        candidate = tokens[-1].rstrip(".") if tokens else v.rstrip(".")
                        # Filtrer IP vs hostname
                        if "." in candidate and not candidate[0].isdigit():
                            # Exclure les IPs
                            try:
                                import ipaddress
                                ipaddress.ip_address(candidate)
                            except ValueError:
                                if candidate != normalized:
                                    all_found.add(candidate.lower())
            except Exception as e:
                result.errors.append(f"DNS records error: {e}")

        # 2. Zone Transfer
        if self.config.do_zone_transfer:
            try:
                zt = attempt_zone_transfer(normalized, resolver=self.resolver)
                result.zone_transfer = zt
                result.sources_used.append("zone_transfer")
                if zt.get("success") and zt.get("records"):
                    from .zone_transfer import extract_domains_from_zone
                    zt_domains = extract_domains_from_zone(zt["records"])
                    all_found.update(zt_domains)
                elif zt.get("errors"):
                    # Not an error, but info
                    result.warnings.extend(zt["errors"][:3])
            except Exception as e:
                result.errors.append(f"Zone transfer error: {e}")

        # 3. Certificate Transparency (crt.sh)
        if self.config.do_ct_logs:
            try:
                ct = query_crtsh(normalized, timeout=self.config.ct_timeout)
                result.ct_logs = ct
                result.sources_used.append("ct_logs")
                if ct.get("domains"):
                    all_found.update(ct["domains"])
                if ct.get("errors"):
                    result.warnings.extend(ct["errors"][:2])
            except Exception as e:
                result.errors.append(f"CT logs error: {e}")

        # 4. Bruteforce
        if self.config.do_bruteforce:
            try:
                bf = bruteforce_subdomains(
                    normalized,
                    wordlist=self.config.wordlist,
                    resolver=self.resolver,
                    max_workers=self.config.bruteforce_workers,
                    timeout=self.config.bruteforce_timeout,
                )
                result.bruteforce = bf
                result.sources_used.append("bruteforce")
                if bf.get("found_domains"):
                    all_found.update(bf["found_domains"])
                if bf.get("wildcard"):
                    result.warnings.append(f"Wildcard DNS détecté ({bf.get('wildcard_ips')}) - faux positifs filtrés")
            except Exception as e:
                result.errors.append(f"Bruteforce error: {e}")

        # 5. Reverse IP (optionnel, seulement si activé)
        # Pour un domaine, on peut faire reverse sur ses IPs pour trouver d'autres domaines sur même serveur
        # ou reverse sur son NS pour trouver tous les domaines hébergés sur ce DNS (cas principal de la demande)
        if self.config.do_reverse_ip:
            try:
                # Si target_type == ns: le but principal est de trouver tous les sites sur ce DNS
                # Donc on fait reverse_ip directement sur le NS hostname
                # Sinon pour un domaine normal, on fait reverse sur son IP et son NS
                candidates = []
                if target_type == "ns":
                    candidates = [normalized]
                else:
                    # domaine normal: son IP + ses NS
                    ips = self.resolver.resolve_ip(normalized)
                    candidates.extend(ips[:2])
                    candidates.extend(result.ns_hosts[:2])

                rev_domains = set()
                rev_by = {}
                for cand in candidates[:3]:  # limiter
                    if not cand:
                        continue
                    rev = reverse_ip_lookup(cand, sources=self.config.reverse_sources, resolver=self.resolver)
                    if rev.get("domains"):
                        rev_domains.update(rev["domains"])
                        rev_by[cand] = rev

                if rev_domains:
                    all_found.update(rev_domains)
                # Stocker le premier comme résultat principal
                if rev_by:
                    # Prendre le plus gros
                    biggest = max(rev_by.values(), key=lambda x: x.get("count", 0))
                    result.reverse_ip = biggest
                    result.sources_used.append("reverse_ip")
            except Exception as e:
                result.errors.append(f"Reverse IP error: {e}")

        # 6. Web check optionnel
        if self.config.do_web_check and all_found:
            try:
                # Limiter à 100 premiers pour éviter trop long
                to_check = list(all_found)[:200]
                wc = bulk_check(to_check, max_workers=self.config.web_check_workers, timeout=self.config.web_check_timeout)
                result.web_checks = wc
                result.sources_used.append("web_check")
            except Exception as e:
                result.errors.append(f"Web check error: {e}")

        # Finalisation
        result.all_domains = clean_domain_list(list(all_found))
        result.all_websites = [f"https://{d}" for d in result.all_domains]
        result.finished_at = time.time()
        result.duration = result.finished_at - started

        return result

    def crawl_many(self, targets: list[str]) -> dict[str, CrawlResult]:
        """Crawl plusieurs cibles"""
        out: dict[str, CrawlResult] = {}
        for t in targets:
            out[t] = self.crawl(t)
        return out
