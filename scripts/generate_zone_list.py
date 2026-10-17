#!/usr/bin/env python3
"""
Génère la liste des domaines d'une zone (ex: .ru, .fr, .com) pour ensuite
énumérer tous les serveurs DNS avec dns_crawl --zone

Sources supportées:
  - crt.sh (Certificate Transparency) : %.ru → tous les domaines ayant eu un certif TLS
  - tranco (top 1M) : top sites filtrés .ru
  - fichier existant (merge)

Usage:
  python scripts/generate_zone_list.py --tld ru --output domaines_ru.txt --sources crt.sh,tranco
  python scripts/generate_zone_list.py --tld ru --output domaines_ru.txt --sources crt.sh --limit 50000
  python scripts/generate_zone_list.py --tld fr --output domaines_fr.txt --sources tranco --limit 10000

Puis:
  dns-crawl --zone ru --input-list domaines_ru.txt -o ns_zone_ru.json
  dns-crawl --zone ru --input-list domaines_ru.txt --crawl-ns -o crawl_zone_ru.json
"""
from __future__ import annotations

import argparse
import re
import json
import time
import sys
from pathlib import Path
from collections import OrderedDict

import requests

# Pour avoir un joli output si rich dispo, sinon fallback print
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

HEADERS = {"User-Agent": "dns_crawl-generate_zone_list/1.0 (OSINT research)"}
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

def is_valid_domain(d: str, tld: str) -> bool:
    d = d.strip().lower().rstrip(".").lstrip("*.").strip()
    if not d or "*" in d or "@" in d or "/" in d or " " in d:
        return False
    if "." not in d:
        return False
    if not DOMAIN_RE.match(d):
        return False
    return d == tld or d.endswith("." + tld)

def clean_and_dedup(domains: list[str], tld: str) -> list[str]:
    seen = OrderedDict()
    for d in domains:
        d = d.strip().lower().rstrip(".").lstrip("*.").lstrip(".")
        if "/" in d:
            d = d.split("/")[0]
        if ":" in d and d.count(":") == 1:
            d = d.split(":")[0]
        if "@" in d:
            d = d.split("@")[-1]
        if not is_valid_domain(d, tld):
            continue
        if d not in seen:
            seen[d] = None
    return list(seen.keys())

# ──────────────────────────────────────────────────────────────────────────────
# Source 1: crt.sh (CT logs)
# ──────────────────────────────────────────────────────────────────────────────

def fetch_crtsh(tld: str, limit: int | None = None, timeout: int = 30) -> tuple[list[str], str]:
    """
    Récupère les domaines .ru via crt.sh: https://crt.sh/?q=%.ru&output=json
    ATTENTION: pour .ru, ça peut être >2M entrées → très volumineux.
    On stream et on déduplique à la volée.
    """
    tld = tld.lstrip(".").lower()
    query = f"%.{tld}"
    url = f"https://crt.sh/?q={query}&output=json"
    log = f"[crt.sh] {query} → {url}"

    try:
        print(f"→ crt.sh: {url}")
        resp = requests.get(url, timeout=timeout, headers=HEADERS)
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        domains: list[str] = []
        for entry in data:
            # name_value peut contenir 1..n lignes (SAN)
            raw = entry.get("name_value", "") or entry.get("common_name", "")
            for line in raw.split("\n"):
                line = line.strip().lower()
                if is_valid_domain(line, tld):
                    domains.append(line)
                elif is_valid_domain(line.lstrip("*."), tld):
                    domains.append(line.lstrip("*."))
            if limit and len(domains) >= limit * 3:  # on récupère large puis on filtrera
                print(f"  [crt.sh] limite intermédiaire atteinte ({len(domains)} brut)")
                break
        # dedup + limit
        cleaned = clean_and_dedup(domains, tld)
        if limit:
            cleaned = cleaned[:limit]
        return cleaned, f"OK ({len(cleaned)} uniques, {len(data)} entrées CT)"
    except requests.exceptions.SSLError as e:
        return [], f"SSL error (sandbox bloque crt.sh ?): {e} → lance ce script EN LOCAL, pas dans Arena sandbox"
    except Exception as e:
        return [], f"Erreur: {e}"

# ──────────────────────────────────────────────────────────────────────────────
# Source 2: Tranco top 1M
# ──────────────────────────────────────────────────────────────────────────────

def fetch_tranco(tld: str, limit: int | None = None) -> tuple[list[str], str]:
    """
    Récupère les domaines .ru depuis Tranco top 1M (https://tranco-list.eu)
    C'est un échantillon représentatif (top sites), pas exhaustif.
    Mais pour .ru, ça donne déjà ~15k domaines .ru dans le top 1M.
    """
    tld = tld.lstrip(".").lower()
    # Tranco a un endpoint stable pour le top 1M zip
    # On tente d'abord le CSV direct, sinon on fallback sur API daily
    urls = [
        "https://tranco-list.eu/top-1m.csv.zip",
        "https://tranco-list.eu/download_daily",
    ]
    # Astuce: le dataset est aussi miroité sur GitHub par des tiers, on tente
    # https://raw.githubusercontent.com/arkadiyt/tranco-top-1m/master/tranco-top-1m.csv
    urls.append("https://raw.githubusercontent.com/arkadiyt/tranco-top-1m/master/tranco-top-1m.csv")

    domains: list[str] = []
    last_err = ""
    for url in urls:
        try:
            print(f"→ tranco: {url}")
            resp = requests.get(url, timeout=20, headers=HEADERS)
            if resp.status_code != 200:
                last_err = f"HTTP {resp.status_code}"
                continue
            # Si zip, on le dézippe
            content = resp.content
            text = ""
            if url.endswith(".zip") or content[:2] == b"PK":
                import io, zipfile
                try:
                    z = zipfile.ZipFile(io.BytesIO(content))
                    # Le zip contient top-1m.csv
                    name = z.namelist()[0]
                    text = z.read(name).decode("utf-8", errors="ignore")
                except Exception as e:
                    # Parfois le serveur renvoie déjà du CSV malgré .zip dans l'URL
                    text = resp.text
            else:
                text = resp.text

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Format Tranco: "rank,domain" ou juste "domain"
                parts = line.split(",")
                candidate = parts[-1].strip().lower().rstrip(".") if parts else ""
                # Filtrer bruit
                if candidate and is_valid_domain(candidate, tld):
                    domains.append(candidate)
                    if limit and len(domains) >= limit:
                        break
            if domains:
                cleaned = clean_and_dedup(domains, tld)
                if limit:
                    cleaned = cleaned[:limit]
                return cleaned, f"OK ({len(cleaned)} uniques via {url})"
            last_err = f"Aucun .{tld} trouvé dans {url} (peut-être liste vide / format changé)"
        except Exception as e:
            last_err = f"{url}: {e}"
            continue

    return [], last_err or "Toutes les sources Tranco ont échoué"

# ──────────────────────────────────────────────────────────────────────────────
# Merge / IO
# ──────────────────────────────────────────────────────────────────────────────

def load_existing(path: Path, tld: str) -> list[str]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if text.strip().startswith("["):
            data = json.loads(text)
            candidates = data if isinstance(data, list) else data.get("domains", [])
            return clean_and_dedup([str(x).lower() for x in candidates if isinstance(x, str)], tld)
        domains = []
        for line in text.splitlines():
            line = line.strip().lower().rstrip(".")
            if line and not line.startswith("#"):
                if "," in line:
                    line = line.split(",")[0].strip()
                domains.append(line)
        return clean_and_dedup(domains, tld)
    except Exception as e:
        print(f"[!] Impossible de charger {path}: {e}")
        return []

FALLBACK_SAMPLES = {
    "ru": [
        "yandex.ru","mail.ru","vk.com","ok.ru","avito.ru","lenta.ru","rambler.ru","gosuslugi.ru","sberbank.ru","wildberries.ru",
        "ozon.ru","drom.ru","aliexpress.ru","beeline.ru","mts.ru","megafon.ru","tele2.ru","rt.ru","rostelecom.ru","pochta.ru",
        "rbc.ru","ria.ru","tass.ru","interfax.ru","kommersant.ru","vedomosti.ru","gazeta.ru","mk.ru","kp.ru","aif.ru",
        "2gis.ru","auto.ru","hh.ru","superjob.ru","litres.ru","championat.ru","sportmaster.ru","eldorado.ru","mvideo.ru",
        "dns-shop.ru","citilink.ru","leroymerlin.ru","perekrestok.ru","magnit.ru","vtb.ru","alfabank.ru","tinkoff.ru",
        "nalog.ru","mos.ru","consultant.ru","kaspersky.ru","ozon.ru","wildberries.ru","sberbank.ru","yandex.net","mail.com",
        "vk.ru","my.mail.ru","cloud.mail.ru","ok.com","avito.com","rbc.com","ria.com","sber.ru","vtb.com","ozon.com",
        "beeline.com","mts.com","megafon.com","tele2.com","rt.com","ria.com","tass.com","consultant.ru","garant.ru","1c.ru"
    ],
    "fr": ["google.fr","leboncoin.fr","orange.fr","free.fr","ovh.com","gandi.net","lemonde.fr","lefigaro.fr","amazon.fr","facebook.fr"],
}

def get_fallback(tld: str) -> list[str]:
    return FALLBACK_SAMPLES.get(tld.lower(), [])

def save_domains(domains: list[str], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Sauvegarde txt (un par ligne)
    path.write_text("\n".join(domains) + "\n", encoding="utf-8")
    # Aussi json côte à côte pour debug
    json_path = path.with_suffix(".json")
    json_path.write_text(json.dumps({"count": len(domains), "domains": domains[:5000]}, indent=2, ensure_ascii=False), encoding="utf-8")
    # Si >5000, on tronque le json mais pas le txt
    if len(domains) > 5000:
        print(f"  [info] JSON tronqué à 5000 pour lisibilité, TXT complet ({len(domains)}).")

def main():
    parser = argparse.ArgumentParser(
        description="Génère la liste des domaines d'une zone (ex: .ru) pour dns_crawl --zone",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Génère liste .ru depuis CT + Tranco, 50k max
  python scripts/generate_zone_list.py --tld ru --output domaines_ru.txt --sources crt.sh,tranco --limit 50000

  # Seulement Tranco (rapide, 15k .ru dans top 1M)
  python scripts/generate_zone_list.py --tld fr --output domaines_fr.txt --sources tranco

  # Reprendre / merger avec fichier existant
  python scripts/generate_zone_list.py --tld ru --output domaines_ru.txt --sources crt.sh --resume

  # Puis énumérer les NS:
  dns-crawl --zone ru --input-list domaines_ru.txt -o ns_zone_ru.json

  # Puis crawler chaque NS (tous les sites dessus):
  dns-crawl --zone ru --input-list domaines_ru.txt --crawl-ns --limit 100 -o crawl_ru.json
        """,
    )
    parser.add_argument("--tld", required=True, help="TLD sans point (ex: ru, fr, com, io)")
    parser.add_argument("--output", "-o", required=True, help="Fichier sortie .txt (un domaine/ligne)")
    parser.add_argument("--sources", default="crt.sh,tranco", help="Sources comma: crt.sh,tranco (défaut: crt.sh,tranco)")
    parser.add_argument("--limit", type=int, default=None, help="Limiter à N domaines (ex: 10000) — utile pour .ru qui a des millions")
    parser.add_argument("--resume", action="store_true", help="Reprendre: merger avec fichier existant au lieu d'écraser")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout crt.sh (défaut 30s)")
    args = parser.parse_args()

    tld = args.tld.strip().lstrip(".").lower()
    output = Path(args.output)
    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    # Normaliser alias
    norm_sources = []
    for s in sources:
        if s in ("crt", "ct", "crt.sh", "crtsh"):
            norm_sources.append("crt.sh")
        elif s in ("tranco", "top1m", "top-1m"):
            norm_sources.append("tranco")
        else:
            norm_sources.append(s)
    sources = norm_sources

    print(f"╔══════════════════════════════════════════════╗")
    print(f"║ Génération liste domaines .{tld}                ")
    print(f"╚══════════════════════════════════════════════╝")
    print(f"TLD: .{tld} | Output: {output} | Limit: {args.limit or '∞'} | Sources: {', '.join(sources)} | Resume: {args.resume}")
    print()

    # Charger existant si resume
    existing: list[str] = []
    if args.resume and output.exists():
        existing = load_existing(output, tld)
        print(f"[resume] {len(existing)} domaines déjà dans {output}")

    all_new: list[str] = []
    stats: list[str] = []

    for src in sources:
        if src == "crt.sh":
            domains, msg = fetch_crtsh(tld, limit=args.limit, timeout=args.timeout)
            print(f"  [{src}] {msg} → {len(domains)} domaines")
            stats.append(f"{src}: {len(domains)} ({msg})")
            all_new.extend(domains)
            time.sleep(1)
        elif src == "tranco":
            domains, msg = fetch_tranco(tld, limit=args.limit)
            print(f"  [{src}] {msg} → {len(domains)} domaines")
            stats.append(f"{src}: {len(domains)} ({msg})")
            all_new.extend(domains)
            time.sleep(1)
        else:
            print(f"[!] Source inconnue: {src} (ignorée)")

        # Early stop si on a déjà atteint limit
        # On estime après dedup, mais on coupe tôt pour éviter trop de requêtes
        if args.limit:
            tmp_dedup = clean_and_dedup(existing + all_new, tld)
            if len(tmp_dedup) >= args.limit:
                print(f"  [limite] {args.limit} atteint, stop sources suivantes")
                break

    # Merge + dedup final
    merged = existing + all_new
    final = clean_and_dedup(merged, tld)
    if args.limit:
        final = final[:args.limit]

    # Sauvegarde
    save_domains(final, output)

    print()
    print(f"✓ Terminé: {len(final)} domaines uniques .{tld} → {output}")
    print(f"  Sources: {'; '.join(stats)}")
    print(f"  Exemple: {', '.join(final[:5])}{'...' if len(final) > 5 else ''}")
    print()
    print("Étapes suivantes:")
    print(f"  1. dns-crawl --zone {tld} --input-list {output} -o ns_zone_{tld}.json")
    print(f"     → énumère tous les NS (ex: 2000 NS uniques pour .ru)")
    print(f"  2. dns-crawl --zone {tld} --input-list {output} --crawl-ns --limit 50 -o crawl_{tld}.json")
    print(f"     → crawl chaque NS (tous les sites dessus)")
    print(f"  3. Voir les NS officiels du TLD: dns-crawl --tld-info --zone {tld}")

    if not final:
        print()
        print("[!] Aucun domaine trouvé. Causes possibles:")
        print("  - En sandbox Arena, crt.sh/tranco sont bloqués → lance ce script EN LOCAL (hors sandbox)")
        print("  - TLD inexistant ou sans CT logs → essaie --sources tranco seul")
        # Fallback: propose échantillon embarqué si .ru
        fallback = get_fallback(tld)
        if fallback:
            print(f"  → Fallback: génération d'un échantillon embarqué de {len(fallback)} domaines .{tld} pour demo offline")
            fallback_cleaned = clean_and_dedup(fallback, tld)
            if args.limit:
                fallback_cleaned = fallback_cleaned[:args.limit]
            save_domains(fallback_cleaned, output)
            print(f"  ✓ Fallback sauvegardé: {len(fallback_cleaned)} domaines → {output}")
            print(f"  Relance: dns-crawl --zone {tld} --input-list {output} -o ns_zone_{tld}.json")
            sys.exit(0)
        sys.exit(2)

if __name__ == "__main__":
    main()
