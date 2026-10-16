"""
Export des résultats du crawler vers différents formats
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional

from .crawler import CrawlResult

class Exporter:
    @staticmethod
    def to_json(result: CrawlResult, path: Optional[str | Path] = None, pretty: bool = True) -> str:
        data = result.to_dict()
        # Ajouter métadonnées
        data["export_type"] = "dns_crawl"
        data["count"] = result.count
        json_str = json.dumps(data, indent=2 if pretty else None, ensure_ascii=False)
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")
        return json_str

    @staticmethod
    def to_txt(result: CrawlResult, path: Optional[str | Path] = None) -> str:
        lines = result.all_domains
        txt = "\n".join(lines) + ("\n" if lines else "")
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(txt, encoding="utf-8")
        return txt

    @staticmethod
    def to_csv(result: CrawlResult, path: Optional[str | Path] = None) -> str:
        """
        CSV avec colonnes: domain, source, ips, type
        """
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["domain", "source", "url", "ips", "is_ns_domain"])

        # Construire mapping domaine -> sources
        # On infère depuis chaque sous-résultat
        domain_sources: dict[str, set[str]] = {}
        domain_ips: dict[str, str] = {}

        # CT
        if result.ct_logs and result.ct_logs.get("domains"):
            for d in result.ct_logs["domains"]:
                domain_sources.setdefault(d, set()).add("ct_logs")
        # Bruteforce
        if result.bruteforce and result.bruteforce.get("found"):
            for entry in result.bruteforce["found"]:
                d = entry["subdomain"]
                domain_sources.setdefault(d, set()).add("bruteforce")
                if entry.get("ips"):
                    domain_ips[d] = ",".join(entry["ips"])
        # Zone transfer
        if result.zone_transfer and result.zone_transfer.get("records"):
            for r in result.zone_transfer["records"]:
                d = r["name"]
                domain_sources.setdefault(d, set()).add("zone_transfer")
        # Reverse
        if result.reverse_ip and result.reverse_ip.get("domains"):
            for d in result.reverse_ip["domains"]:
                domain_sources.setdefault(d, set()).add("reverse_ip")
        if result.reverse_ptr and result.reverse_ptr.get("domains"):
            for d in result.reverse_ptr["domains"]:
                domain_sources.setdefault(d, set()).add("reverse_ptr")

        # Web check
        web_alive_map = {}
        if result.web_checks:
            for d, wc in result.web_checks.items():
                web_alive_map[d] = wc.get("alive")

        # Tous les domaines
        for d in result.all_domains:
            sources = ",".join(sorted(domain_sources.get(d, set()))) or "unknown"
            ips = domain_ips.get(d, "")
            # Si pas d'IPS dans bruteforce, essayer de deviner via dns_records ?
            if not ips and result.dns_records:
                pass
            is_ns = "ns" in result.target_type
            writer.writerow([d, sources, f"https://{d}", ips, is_ns])

        csv_str = output.getvalue()
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(csv_str, encoding="utf-8")
        return csv_str

    @staticmethod
    def to_hosts_file(result: CrawlResult, path: Optional[str | Path] = None) -> str:
        """Format /etc/hosts like"""
        lines = []
        for d in result.all_domains:
            lines.append(f"# {d} - https://{d}")
        txt = "\n".join(lines) + "\n" if lines else ""
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(txt, encoding="utf-8")
        return txt

    @staticmethod
    def export_all(result: CrawlResult, base_path: str | Path, formats: list[str] = None):
        """
        Exporte dans plusieurs formats à partir d'un chemin base
        base_path: sans extension, ex: "output/example.com"
        formats: ["json", "txt", "csv"]
        """
        formats = formats or ["json", "txt", "csv"]
        p = Path(base_path)
        out = {}
        if "json" in formats:
            out["json"] = Exporter.to_json(result, p.with_suffix(".json"))
        if "txt" in formats:
            out["txt"] = Exporter.to_txt(result, p.with_suffix(".txt"))
        if "csv" in formats:
            out["csv"] = Exporter.to_csv(result, p.with_suffix(".csv"))
        if "hosts" in formats:
            out["hosts"] = Exporter.to_hosts_file(result, p.with_suffix(".hosts"))
        return out
