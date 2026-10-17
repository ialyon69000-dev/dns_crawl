"""
CLI pour dns_crawl
Usage:
  dns-crawl example.com
  dns-crawl ns1.ovh.net --reverse --output result.json
  dns-crawl 8.8.8.8 --type ip --no-bruteforce
  dns-crawl example.com --wordlist wordlists/subdomains-large.txt --web-check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from .crawler import DnsCrawler, CrawlConfig
from .utils import normalize_target, detect_target_type
from .export import Exporter

console = Console()

BANNER = r"""
[bold cyan]╔═══════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan] [bold white]  D N S   C R A W L[/bold white]   [dim]v1.0.0[/dim]      [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan] [dim]Énumère tous les sites sur un DNS[/dim] [bold cyan]║[/bold cyan]
[bold cyan]╚═══════════════════════════════════════╝[/bold cyan]
"""

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dns-crawl",
        description="Crawler DNS - Obtenir tous les sites webs référencés sur un DNS / domaine / NS / IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  dns-crawl example.com
  dns-crawl example.com --wordlist top100 --no-ct --no-bruteforce
  dns-crawl ns1.ovh.net --reverse  (trouve tous les domaines sur ce NS)
  dns-crawl 1.1.1.0/24 --type cidr
  dns-crawl example.com -o resultats.json --format json,csv,txt
  dns-crawl example.com --web-check  (vérifie HTTP/HTTPS)
  dns-crawl example.com --resolvers 1.1.1.1,8.8.8.8

Techniques utilisées:
  • DNS records (A, MX, NS, TXT, SOA, CAA...)
  • Zone transfer (AXFR)
  • Certificate Transparency (crt.sh)
  • Bruteforce dictionnaire (~200 sous-domaines par défaut)
  • Reverse IP / Reverse NS (OSINT)
        """,
    )
    p.add_argument("target", nargs="?", help="Domaine, NS hostname, IP ou CIDR (ex: example.com, ns1.ovh.net, 8.8.8.8, 192.168.1.0/24). Pour une zone entière, utilisez --zone .ru")
    p.add_argument("--type", choices=["auto", "domain", "ns", "ip", "cidr"], default="auto", help="Forcer le type de cible (défaut: auto-détection)")

    # Zone entière (TLD) - nouveau
    gz = p.add_argument_group("Zone entière (ex: .ru, .fr, .com)")
    gz.add_argument("--zone", dest="zone", help="Énumérer tous les serveurs DNS d'une zone (ex: --zone ru, --zone .ru, --zone fr). Nécessite une liste de domaines via --input-list ou --sources")
    gz.add_argument("--enum-ns", dest="enum_ns", action="store_true", help="Alias de --zone: énumère les NS uniques de la zone et leurs stats")
    gz.add_argument("--input-list", dest="input_list", help="Fichier avec liste de domaines de la zone (un par ligne, txt/csv/json)")
    gz.add_argument("--limit", type=int, default=None, help="Limiter le nombre de domaines traités (pour test, ex: --limit 1000)")
    gz.add_argument("--sources", dest="sources", help="Sources pour récupérer domaines si pas de fichier: crt.sh,tranco (ex: --sources crt.sh --zone ru)")
    gz.add_argument("--crawl-ns", dest="crawl_ns", action="store_true", help="Après énumération, crawler chaque NS trouvé (mode lourd, utiliser --limit pour tester)")
    gz.add_argument("--tld-info", dest="tld_info", action="store_true", help="Affiche seulement les NS du TLD lui-même (dig NS ru), rapide")

    # Options techniques
    g = p.add_argument_group("Techniques")
    g.add_argument("--no-ct", dest="no_ct", action="store_true", help="Désactiver Certificate Transparency (crt.sh)")
    g.add_argument("--no-bruteforce", dest="no_bruteforce", action="store_true", help="Désactiver bruteforce dictionnaire")
    g.add_argument("--no-zone-transfer", dest="no_zone_transfer", action="store_true", help="Désactiver tentative AXFR")
    g.add_argument("--reverse", dest="do_reverse", action="store_true", help="Activer reverse IP/NS (trouver tous les domaines sur même serveur DNS/IP)")
    g.add_argument("--web-check", dest="web_check", action="store_true", help="Vérifier HTTP/HTTPS sur chaque domaine trouvé")

    # Params
    g2 = p.add_argument_group("Paramètres")
    g2.add_argument("-w", "--wordlist", dest="wordlist", help="Wordlist pour bruteforce: chemin fichier, 'top100', 'common', 'large' ou liste comma-separated")
    g2.add_argument("--workers", type=int, default=50, help="Threads pour bruteforce (défaut 50)")
    g2.add_argument("--resolvers", help="Serveurs DNS custom (comma-separated, ex: 1.1.1.1,8.8.8.8)")
    g2.add_argument("--timeout", type=float, default=3.0, help="Timeout DNS en secondes (défaut 3.0)")
    g2.add_argument("--ct-timeout", type=int, default=15, help="Timeout crt.sh (défaut 15)")

    # Sortie
    g3 = p.add_argument_group("Sortie")
    g3.add_argument("-o", "--output", help="Fichier de sortie (extension détermine format: .json/.txt/.csv; sans extension => base pour multi-format)")
    g3.add_argument("--format", dest="out_format", default="json", help="Format(s) de sortie: json, txt, csv, hosts ou combo comma (défaut: json)")
    g3.add_argument("--pretty", action="store_true", help="JSON pretty print + couleur")
    g3.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    g3.add_argument("-q", "--quiet", action="store_true", help="Sortie minimale (juste liste domaines)")

    # Autres
    p.add_argument("--list-wordlists", action="store_true", help="Lister les wordlists disponibles et quitter")
    p.add_argument("--version", action="store_true", help="Afficher version et quitter")

    return p


def list_wordlists_and_exit():
    console.print(BANNER)
    table = Table(title="Wordlists disponibles", box=box.ROUNDED)
    table.add_column("Nom", style="cyan")
    table.add_column("Chemin / Description", style="white")
    table.add_column("Taille", style="green")

    # Chercher
    candidates = [
        ("top100", "Top 100 sous-domaines communs", "~100"),
        ("common", "wordlists/subdomains-common.txt", "~200 (défaut)"),
        ("large", "wordlists/subdomains-large.txt / top500+", "~500-1000"),
    ]
    for name, desc, size in candidates:
        table.add_row(name, desc, size)

    # Fichiers réels
    wl_dir = Path(__file__).parent.parent / "wordlists"
    if wl_dir.exists():
        for f in wl_dir.glob("*.txt"):
            try:
                count = len([l for l in f.read_text().splitlines() if l.strip() and not l.startswith("#")])
                table.add_row(str(f.name), str(f), str(count))
            except Exception:
                pass

    console.print(table)
    console.print("\n[dim]Usage: --wordlist common / --wordlist wordlists/monfichier.txt / --wordlist www,mail,api,admin[/dim]")
    sys.exit(0)


def print_result(result, quiet: bool = False, pretty: bool = False):
    if quiet:
        for d in result.all_domains:
            console.print(d)
        return

    console.print(BANNER)
    # Résumé
    console.print(Panel(result.summary(), title=f"[bold green]✓ Crawl terminé[/bold green] [dim]({result.duration:.2f}s)[/dim]", border_style="green"))

    # DNS records
    if result.dns_records:
        table = Table(title=f"Enregistrements DNS - {result.normalized}", box=box.ROUNDED, show_lines=False)
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Valeurs", style="white")
        for k, vals in result.dns_records.items():
            vals_str = "\n".join(vals[:5]) + (f"\n[dim]+{len(vals)-5} autres[/dim]" if len(vals) > 5 else "")
            table.add_row(k, vals_str)
        if result.ns_hosts:
            table.add_row("[bold]NS[/bold]", "\n".join(result.ns_hosts))
        console.print(table)

    # Zone transfer
    if result.zone_transfer:
        zt = result.zone_transfer
        status = "[green]SUCCÈS[/green]" if zt["success"] else "[red]REFUSÉ (normal)[/red]"
        console.print(Panel(
            f"Status: {status}\nRecords: {zt['count']}\nNS testés: {', '.join(zt['attempted_ns'])}\n" +
            (f"Erreurs: {'; '.join(zt['errors'][:2])}" if zt["errors"] else ""),
            title="Zone Transfer (AXFR)", border_style="yellow" if not zt["success"] else "green"
        ))

    # CT logs
    if result.ct_logs:
        ct = result.ct_logs
        console.print(Panel(
            f"Requêtes: {', '.join(ct.get('queries', []))}\nDomaines: {len(ct.get('domains', []))}\nEntrées CT: {ct.get('raw_count',0)}\n" +
            (f"[dim]{ct['error'][:200]}[/dim]" if ct.get("error") else ""),
            title="Certificate Transparency (crt.sh)", border_style="blue"
        ))

    # Bruteforce
    if result.bruteforce:
        bf = result.bruteforce
        table = Table(title=f"Bruteforce dictionnaire ({bf['tried']} testés, wildcard={bf['wildcard']})", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Sous-domaine", style="cyan")
        table.add_column("IPs / CNAME", style="white")
        table.add_column("Type", style="green", width=12)
        for i, entry in enumerate(bf.get("found", [])[:30], 1):
            ips = ", ".join(entry.get("ips", [])[:2]) or ", ".join(entry.get("cname", [])[:1]) or "-"
            table.add_row(str(i), entry["subdomain"], ips, ",".join(entry.get("record_types", [])))
        if len(bf.get("found", [])) > 30:
            table.add_row("...", f"[dim]+{len(bf['found'])-30} autres[/dim]", "", "")
        table.add_row("", f"[bold]Total: {len(bf.get('found_domains', []))}[/bold]", "", "")
        console.print(table)

    # Reverse
    if result.reverse_ip and result.reverse_ip.get("count", 0) > 0:
        rip = result.reverse_ip
        table = Table(title=f"Reverse IP/NS - {rip.get('target')} ({rip.get('count')} domaines)", box=box.ROUNDED)
        table.add_column("Domaine", style="cyan")
        table.add_column("Source", style="dim")
        for d in rip.get("domains", [])[:30]:
            table.add_row(d, ",".join(rip.get("sources_used", [])))
        if len(rip.get("domains", [])) > 30:
            table.add_row(f"[dim]+{len(rip['domains'])-30} autres[/dim]", "")
        console.print(table)

    if result.reverse_ptr and result.reverse_ptr.get("count", 0) > 0:
        rptr = result.reverse_ptr
        table = Table(title=f"Reverse PTR ({rptr.get('ips_scanned')} IPs scannées)", box=box.ROUNDED)
        table.add_column("IP", style="cyan")
        table.add_column("PTR", style="white")
        for entry in rptr.get("results", [])[:20]:
            table.add_row(entry["ip"], ", ".join(entry["ptr"]))
        console.print(table)

    # Web check
    if result.web_checks:
        alive = [(d, v) for d, v in result.web_checks.items() if v.get("alive")]
        dead = [(d, v) for d, v in result.web_checks.items() if not v.get("alive")]
        table = Table(title=f"Vérification Web (alive: {len(alive)}/{len(result.web_checks)})", box=box.ROUNDED)
        table.add_column("Domaine", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Titre / URL", style="dim")
        for d, wc in alive[:20]:
            best = wc.get("best", {})
            table.add_row(d, str(best.get("status", "")), best.get("title", "") or best.get("final_url", "")[:60])
        if len(alive) > 20:
            table.add_row(f"[dim]+{len(alive)-20} autres alive[/dim]", "", "")
        console.print(table)

    # Résultat final
    console.print("\n[bold white]═══ Tous les domaines / sites trouvés ({}) ═══[/bold white]".format(result.count))
    if result.all_domains:
        # Afficher en colonnes 3 par ligne pour lisibilité
        table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        table.add_column("Domaines", style="green")
        # Group by 1 per row for clarity
        for d in result.all_domains:
            table.add_row(f"• {d}  [dim]https://{d}[/dim]")
        console.print(table)
    else:
        console.print("[yellow]Aucun domaine trouvé. Essayez avec --reverse ou une autre wordlist.[/yellow]")

    if result.errors:
        console.print(Panel("\n".join(result.errors), title="[red]Erreurs[/red]", border_style="red"))
    if result.warnings:
        console.print(Panel("\n".join(result.warnings), title="[yellow]Warnings[/yellow]", border_style="yellow"))

    # Commande export
    console.print(f"\n[dim]Exporter: dns-crawl {result.target} -o output.json  ou  -o output.txt  ou  --format json,csv,txt[/dim]")


def _handle_zone_mode(args):
    """Gère --zone / --enum-ns / --tld-info en mode zone entière"""
    from .zone_enum import crawl_ns_zone, get_tld_nameservers, crawl_all_ns
    from .resolver import DnsResolver
    import json

    zone = (args.zone or "").strip().lstrip(".")
    # --tld-info seul: juste afficher les NS du TLD
    if args.tld_info and zone:
        console.print(BANNER)
        console.print(f"[dim]Zone TLD demandée:[/dim] [bold white].{zone}[/bold white]")
        res = get_tld_nameservers(zone)
        if not res["success"]:
            console.print(f"[red]Échec NS TLD .{zone} : aucun NS trouvé[/red]")
            sys.exit(1)
        table = Table(title=f"Serveurs DNS autoritaires du TLD .{zone} ({res['ns_count']})", box=box.ROUNDED)
        table.add_column("NS hostname", style="cyan")
        table.add_column("IPs", style="white")
        for ns, det in res["details"].items():
            ips = ", ".join(det["ips"][:3]) if det["ips"] else "[dim]—[/dim]"
            table.add_row(ns, ips)
        console.print(table)
        console.print(f"\n[dim]Pour énumérer TOUS les NS hébergeant des domaines .{zone}, utilisez:[/dim]")
        console.print(f"[white]  dns-crawl --zone {zone} --input-list domaines_{zone}.txt --limit 5000[/white]")
        console.print(f"[white]  dns-crawl --zone {zone} --sources crt.sh --limit 2000[/white]")
        if args.output:
            Path(args.output).write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
            console.print(f"[green]✓ Exporté vers {args.output}[/green]")
        sys.exit(0)

    # Mode --zone / --enum-ns
    if zone:
        console.print(BANNER)
        console.print(f"[bold cyan]═══ Énumération zone .{zone} ═══[/bold cyan]")
        # Résolveur custom si fourni
        resolvers = [r.strip() for r in args.resolvers.split(",")] if args.resolvers else None
        resolver = DnsResolver(nameservers=resolvers, timeout=args.timeout) if resolvers else DnsResolver(timeout=args.timeout)

        # Afficher d'abord les NS du TLD lui-même
        tld_ns_info = get_tld_nameservers(zone, resolver=resolver)
        if tld_ns_info["success"]:
            console.print(Panel(
                f"TLD .{zone} géré par {tld_ns_info['ns_count']} serveurs:\n" + ", ".join(tld_ns_info["ns_hosts"]),
                title=f"NS du TLD .{zone}", border_style="blue"
            ))

        # Sources
        sources = [s.strip().lower() for s in args.sources.split(",")] if args.sources else None
        if args.input_list and not Path(args.input_list).exists():
            console.print(f"[red]Fichier introuvable: {args.input_list}[/red]")
            sys.exit(1)

        console.print(f"[dim]Énumération des NS pour .{zone}... (limit={args.limit or '∞'}, workers={args.workers})[/dim]")
        console.print(f"[dim]Sources: {args.input_list or sources or 'auto'}[/dim]")

        result = crawl_ns_zone(
            tld=zone,
            input_file=args.input_list,
            limit=args.limit,
            max_workers=args.workers,
            resolver=resolver,
            sources=sources,
        )

        if not result.get("success"):
            console.print(f"[red]Erreur: {result.get('error')}[/red]")
            sys.exit(1)

        # Afficher résultats
        enum = result["ns_enumeration"]
        console.print(Panel(
            f"Domaines traités: {result['domains_total']} (source: {result['domains_source']})\n"
            f"Domaines avec NS: {enum['domains_with_ns']} / sans NS: {enum['domains_without_ns']}\n"
            f"NS uniques trouvés: [bold green]{enum['ns_count']}[/bold green]\n"
            f"Durée: {result['duration']:.2f}s",
            title=f"✓ Zone .{zone} énumérée", border_style="green"
        ))

        # Top NS
        table = Table(title=f"Top serveurs DNS hébergeant du .{zone} (sur {enum['domains_with_ns']} domaines)", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("NS hostname", style="cyan")
        table.add_column("Domaines", style="white", justify="right")
        table.add_column("%", style="green", justify="right")
        table.add_column("IPs", style="dim")
        for i, (ns, cnt) in enumerate(enum["top_ns"][:20], 1):
            det = result["ns_details"].get(ns, {})
            pct = det.get("percent", 0)
            ips = ", ".join(det.get("ips", [])[:2]) if det.get("ips") else "—"
            table.add_row(str(i), ns, str(cnt), f"{pct}%", ips)
        console.print(table)

        # Toutes les NS si --verbose
        if args.verbose:
            console.print(f"\n[dim]Liste complète ({enum['ns_count']} NS):[/dim]")
            for ns in enum["ns_list"]:
                console.print(f"  • {ns} ({enum['ns_counter'][ns]} domaines)")

        # Crawl chaque NS si demandé
        if args.crawl_ns:
            console.print(f"\n[bold yellow]▶ Crawl de chaque NS ({min(len(enum['ns_list']), args.limit or len(enum['ns_list'])) } NS) → tous les sites dessus...[/bold yellow]")
            crawl_res = crawl_all_ns(enum["ns_list"], max_workers=10, limit_ns=args.limit)
            table2 = Table(title="Crawl reverse de chaque NS (tous les sites dessus)", box=box.ROUNDED)
            table2.add_column("NS", style="cyan")
            table2.add_column("Sites trouvés", style="white", justify="right")
            for ns, data in crawl_res["per_ns"].items():
                cnt = data.get("count", 0) if data.get("success") else f"err: {data.get('error','')[:20]}"
                table2.add_row(ns, str(cnt))
            console.print(table2)
            console.print(f"[dim]Total unique across all NS: {crawl_res['total_unique_domains_across_all_ns']}[/dim]")
            # Merger avec result pour export
            result["crawl_ns_results"] = crawl_res

        # Export
        if args.output:
            out_path = Path(args.output)
            known_exts = {"json", "txt", "csv"}
            ext = out_path.suffix.lstrip(".").lower()
            # Pour zone, on force json si pas précisé, txt = liste NS
            if ext == "txt":
                # Export simple: liste NS
                out_path.write_text("\n".join(enum["ns_list"]) + "\n", encoding="utf-8")
                console.print(f"[green]✓ Exporté NS list vers {out_path} ({enum['ns_count']} NS)[/green]")
            elif ext == "csv":
                import csv
                with out_path.open("w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["ns_hostname", "domain_count", "percent", "ips"])
                    for ns, cnt in enum["top_ns"]:
                        det = result["ns_details"].get(ns, {})
                        w.writerow([ns, cnt, det.get("percent",""), ",".join(det.get("ips", []))])
                console.print(f"[green]✓ Exporté CSV vers {out_path}[/green]")
            else:
                # JSON complet
                if not ext:
                    out_path = out_path.with_suffix(".json")
                out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                console.print(f"[green]✓ Exporté JSON vers {out_path} ({enum['ns_count']} NS, {result['domains_total']} domaines)[/green]")
        else:
            console.print(f"\n[dim]Exporter: dns-crawl --zone {zone} --limit 1000 -o output_zone_{zone}.json[/dim]")
            console.print(f"[dim]Pour crawler chaque NS: ajoutez --crawl-ns[/dim]")

        sys.exit(0)
    elif args.enum_ns:
        console.print("[red]--enum-ns nécessite --zone (ex: --zone ru)[/red]")
        sys.exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        from . import __version__
        console.print(f"dns_crawl v{__version__}")
        sys.exit(0)

    if args.list_wordlists:
        list_wordlists_and_exit()

    # Mode zone prioritaire (ne nécessite pas target)
    if args.zone or args.tld_info or args.enum_ns:
        _handle_zone_mode(args)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target.strip()
    # Config
    resolvers = None
    if args.resolvers:
        resolvers = [r.strip() for r in args.resolvers.split(",") if r.strip()]

    config = CrawlConfig(
        do_resolve_all=True,
        do_zone_transfer=not args.no_zone_transfer,
        do_ct_logs=not args.no_ct,
        do_bruteforce=not args.no_bruteforce,
        do_reverse_ip=args.do_reverse,
        do_web_check=args.web_check,
        wordlist=args.wordlist,
        bruteforce_workers=args.workers,
        bruteforce_timeout=args.timeout,
        resolvers=resolvers,
        dns_timeout=args.timeout,
        ct_timeout=args.ct_timeout,
        verbose=args.verbose,
    )

    if not args.quiet:
        console.print(BANNER)
        console.print(f"[dim]Cible:[/dim] [bold white]{target}[/bold white] [dim]type:{args.type}[/dim]")
        console.print(f"[dim]Techniques:[/dim] DNS={'oui' if config.do_resolve_all else 'non'} | CT={'oui' if config.do_ct_logs else 'non'} | Bruteforce={'oui' if config.do_bruteforce else 'non'} | AXFR={'oui' if config.do_zone_transfer else 'non'} | Reverse={'oui' if config.do_reverse_ip else 'non'} | WebCheck={'oui' if config.do_web_check else 'non'}")
        console.print("[dim]Lancement... (peut prendre 10-30s selon techniques)[/dim]\n")

    crawler = DnsCrawler(config=config)

    try:
        # Progress simple si non quiet
        if args.quiet or args.verbose:
            result = crawler.crawl(target)
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task(description="Crawl DNS en cours...", total=None)
                result = crawler.crawl(target)
                progress.update(task, completed=True)

        # Affichage
        print_result(result, quiet=args.quiet, pretty=args.pretty)

        # Export si demandé
        if args.output:
            out_path = Path(args.output)
            formats = [f.strip().lower() for f in args.out_format.split(",")]

            # Si output a une extension connue, on respecte
            known_exts = {"json", "txt", "csv", "hosts"}
            ext = out_path.suffix.lstrip(".").lower()
            if ext in known_exts and len(formats) == 1 and formats[0] == "json":
                # L'utilisateur a donné result.json mais n'a pas spécifié format -> déduire de l'extension
                # Si format explicit est json par défaut, mais fichier est .txt -> utiliser txt
                formats = [ext]
            elif ext in known_exts and args.out_format == "json":
                # Heuristique: si fichier est .txt et format par défaut json -> switch à txt
                # On ne le fait que si l'utilisateur n'a pas explicitement mis --format
                # Pour simplicité: si output extension != json et format == json (défaut), utiliser extension
                if ext != "json":
                    formats = [ext]

            # Cas multi-format: output sans extension ou avec base
            # Si l'utilisateur met output.json avec --format json,csv -> on doit créer output.json + output.csv
            # On gère: si format contient plusieurs, traiter output comme base (sans extension)
            if len(formats) > 1:
                base = out_path.with_suffix("") if out_path.suffix else out_path
                # Si output est "resultats.json" et formats=json,csv -> base = "resultats"
                exported = Exporter.export_all(result, base, formats=formats)
                console.print(f"\n[green]✓ Exporté:[/green] {', '.join(str(base.with_suffix('.'+f)) for f in formats)}")
            else:
                fmt = formats[0]
                if fmt == "json":
                    Exporter.to_json(result, out_path, pretty=True)
                elif fmt == "txt":
                    Exporter.to_txt(result, out_path)
                elif fmt == "csv":
                    Exporter.to_csv(result, out_path)
                elif fmt == "hosts":
                    Exporter.to_hosts_file(result, out_path)
                else:
                    Exporter.to_json(result, out_path.with_suffix(".json"))
                    fmt = "json"
                console.print(f"\n[green]✓ Exporté vers {out_path} (format {fmt}, {result.count} domaines)[/green]")

        # Exit code: 0 si trouvé au moins 1, 1 si rien
        sys.exit(0 if result.count > 0 else 2)

    except KeyboardInterrupt:
        console.print("\n[red]Interrompu par l'utilisateur[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Erreur fatale: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
