"""
Certificate Transparency logs via crt.sh
Permet d'énumérer tous les domaines / sous-domaines ayant eu un certificat TLS
C'est l'une des méthodes les plus efficaces pour trouver des sous-domaines.
"""
from __future__ import annotations

import re
import time
import requests
from typing import Optional

from .utils import clean_domain_list


CRT_SH_URL = "https://crt.sh/"
# API JSON: https://crt.sh/?q=example.com&output=json
# On utilise aussi le wildcard: %.example.com (crt.sh le supporte)

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def query_crtsh(domain: str, wildcard: bool = True, timeout: int = 15, retries: int = 2) -> dict:
    """
    Interroge crt.sh pour un domaine.
    domain: ex "example.com" ou "*.example.com"
    wildcard: si True, cherche aussi %.example.com
    Retourne dict avec:
      - success: bool
      - domains: list[str] (dédupliqués)
      - raw_count: nombre d'entrées CT
      - error: str | None
    """
    results_domains: set[str] = set()
    errors: list[str] = []
    raw_count = 0

    queries = [domain]
    if wildcard and not domain.startswith("%.") and not domain.startswith("*."):
        queries.append(f"%.{domain}")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "dns_crawl/1.0 (OSINT DNS enumeration)",
        "Accept": "application/json",
    })

    for q in queries:
        url = f"{CRT_SH_URL}?q={q}&output=json"
        attempt = 0
        while attempt <= retries:
            try:
                resp = session.get(url, timeout=timeout)
                raw_count_note = f" {resp.status_code} "

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception as je:
                        # Parfois crt.sh renvoie du HTML si rate limit
                        errors.append(f"JSON parse error for {q}: {je} - body start: {resp.text[:200]}")
                        break

                    raw_count += len(data) if isinstance(data, list) else 0
                    for entry in data:
                        # entry contient: common_name, name_value, etc.
                        # name_value peut contenir plusieurs lignes (SAN)
                        name_value = entry.get("name_value", "")
                        common_name = entry.get("common_name", "")

                        for raw in [name_value, common_name]:
                            if not raw:
                                continue
                            # name_value peut être multi-lignes
                            for line in raw.split("\n"):
                                line = line.strip().lower().rstrip(".").lstrip("*.")
                                if not line:
                                    continue
                                # Nettoyage
                                line = line.lstrip("*.").strip()
                                if "@" in line:
                                    # Ne pas garder les emails
                                    continue
                                if line.startswith("*"):
                                    line = line.lstrip("*.")
                                # Filtre basique
                                if "." not in line:
                                    continue
                                # Exclure les wildcards restants
                                if "*" in line:
                                    continue
                                results_domains.add(line)
                    break  # succès, sortir retry loop

                elif resp.status_code in (429, 503, 504):
                    # Rate limit / overload -> attendre et retry
                    wait = 2 ** attempt
                    errors.append(f"crt.sh rate limited for {q} (HTTP {resp.status_code}), retry in {wait}s")
                    time.sleep(wait)
                    attempt += 1
                    continue
                else:
                    errors.append(f"crt.sh HTTP {resp.status_code} for {q}: {resp.text[:300]}")
                    break

            except requests.exceptions.Timeout:
                errors.append(f"crt.sh timeout for {q} (attempt {attempt+1}/{retries+1})")
                attempt += 1
                time.sleep(1)
                continue
            except requests.exceptions.ConnectionError as e:
                errors.append(f"crt.sh connection error for {q}: {e}")
                attempt += 1
                time.sleep(1)
                continue
            except Exception as e:
                errors.append(f"crt.sh error for {q}: {e}")
                break
        # Petite pause entre les deux queries pour être gentil avec crt.sh
        if len(queries) > 1:
            time.sleep(0.5)

    # Post-traitement: garder seulement domaines pertinents
    # crt.sh peut renvoyer des domaines apparentés mais pas du target
    # On garde tout par défaut, mais on peut filtrer par suffix
    # Pour l'instant on garde tout et on laisse l'utilisateur filtrer
    cleaned = clean_domain_list(list(results_domains))

    # Filtrage optionnel: ne garder que les domaines qui contiennent la base domain
    # Ex: pour example.com, on garde sub.example.com, mais crt.sh peut renvoyer other.com via SAN multi-domain
    # On garde tout, mais on note le count filtré
    # Alternative: fournir les deux
    base = domain.lstrip("%").lstrip(".").lstrip("*").lower()
    filtered = [d for d in cleaned if d == base or d.endswith("." + base)]
    # Mais on garde aussi l'autre liste pour debug
    # Par défaut on retourne filtered s'il y en a, sinon tout
    final_list = filtered if filtered else cleaned

    return {
        "success": len(final_list) > 0,
        "domains": sorted(final_list),
        "domains_all": cleaned,  # tous, y compris cross-domain SAN
        "raw_count": raw_count,
        "queries": queries,
        "errors": errors,
        "error": "; ".join(errors) if errors else None,
    }


def query_crtsh_simple(domain: str, timeout: int = 15) -> list[str]:
    """Wrapper simple retournant juste la liste de domaines"""
    res = query_crtsh(domain, timeout=timeout)
    return res.get("domains", [])
