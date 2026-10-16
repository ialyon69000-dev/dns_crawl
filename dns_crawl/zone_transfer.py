"""
Tentative de transfert de zone AXFR
Si le serveur DNS est mal configuré, il peut donner toute la zone.
"""
from __future__ import annotations

import dns.zone
import dns.query
import dns.rdatatype
from typing import Optional

from .resolver import DnsResolver


def attempt_zone_transfer(domain: str, resolver: Optional[DnsResolver] = None) -> dict:
    """
    Tente un AXFR sur tous les NS du domaine.
    Retourne dict avec:
    - success: bool
    - records: list[dict] si succès
    - attempted_ns: list[str]
    - errors: list[str]
    """
    res = resolver or DnsResolver()
    ns_hosts = res.get_ns(domain)
    # Fallback: essayer aussi via SOA
    soa = res.get_soa(domain)
    if not ns_hosts and soa:
        try:
            mname = soa[0].split()[0].rstrip(".")
            if mname:
                ns_hosts = [mname]
        except Exception:
            pass

    if not ns_hosts:
        # Dernier fallback: essayer le domaine lui-même comme NS (cas rare)
        ns_hosts = [domain]

    records: list[dict] = []
    errors: list[str] = []
    success = False
    attempted_ns: list[str] = []

    for ns_host in ns_hosts:
        attempted_ns.append(ns_host)
        # Résoudre IP du NS
        ns_ips = res.resolve_ip(ns_host)
        if not ns_ips:
            # essayer de query directement le hostname (dns.query.xfr peut résoudre)
            ns_ips = [ns_host]

        for ns_ip in ns_ips:
            try:
                # dns.query.xfr fait l'AXFR
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5, lifetime=10))
                if zone:
                    # Parcourir la zone
                    for name, node in zone.nodes.items():
                        # name est relatif à l'origin
                        fqdn = name.to_text()
                        if fqdn == "@":
                            fqdn = domain
                        elif not fqdn.endswith(domain):
                            fqdn = f"{fqdn}.{domain}" if fqdn != "@" else domain
                        # Normaliser
                        fqdn = fqdn.rstrip(".")

                        for rdataset in node.rdatasets:
                            rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                            for rdata in rdataset:
                                records.append({
                                    "name": fqdn,
                                    "type": rdtype,
                                    "value": rdata.to_text(),
                                    "ttl": rdataset.ttl,
                                    "ns_source": ns_host,
                                })
                    success = True
                    # Pas besoin de tester autres NS si succès (mais on continue pour exhaustivité)
                    break
            except dns.exception.FormError as e:
                errors.append(f"{ns_host} ({ns_ip}): FormError / transfert refusé: {e}")
            except dns.query.TransferError as e:
                errors.append(f"{ns_host} ({ns_ip}): TransferError: {e}")
            except Exception as e:
                # Inclure timeout, REFUSED, etc.
                err_msg = str(e) or type(e).__name__
                # Messages courants: "Transfer failed, status: REFUSED"
                errors.append(f"{ns_host} ({ns_ip}): {err_msg}")
                continue
        if success:
            break

    # Dédup records
    # Transformer en set via tuple pour enlever doublons
    seen = set()
    deduped = []
    for r in records:
        key = (r["name"], r["type"], r["value"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return {
        "success": success,
        "domain": domain,
        "records": deduped,
        "attempted_ns": attempted_ns,
        "errors": errors,
        "count": len(deduped),
    }


def extract_domains_from_zone(records: list[dict]) -> list[str]:
    """Extrait la liste des domaines/noms depuis les records de zone"""
    domains = set()
    for r in records:
        domains.add(r["name"])
        # Aussi parser les valeurs qui sont des hostnames (MX, NS, CNAME, etc.)
        val = r["value"].strip().rstrip(".")
        # Heuristique: si value ressemble à un hostname et contient le domaine ou un point
        if "." in val and " " not in val:
            # Pour MX: "10 mail.example.com." -> on a déjà gardé le host via to_text, mais split
            parts = val.split()
            candidate = parts[-1].rstrip(".") if parts else val
            if "." in candidate:
                domains.add(candidate)
    return sorted(domains)
