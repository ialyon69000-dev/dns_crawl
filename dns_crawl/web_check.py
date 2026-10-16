"""
Vérification HTTP/HTTPS pour confirmer qu'un domaine héberge un site web
Optionnel, mais utile pour filtrer les résultats DNS qui n'ont pas de site.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

DEFAULT_TIMEOUT = 5
DEFAULT_UA = "dns_crawl/1.0 (Mozilla/5.0 compatible; Site enumeration)"

def check_website(
    domain: str,
    timeout: int = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    check_https: bool = True,
    check_http: bool = True,
) -> dict:
    """
    Vérifie si un domaine a un site web accessible.
    Teste https puis http.
    Retourne dict avec status, url finale, titre, etc.
    """
    domain = domain.strip().rstrip("/").lower()
    # Enlever schéma si présent
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0].split(":")[0]

    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_UA})
    # Ne pas vérifier trop strictement les certificats pour l'énumération
    # Mais on garde verify=True par défaut pour sécurité, fallback à False si échec certificat

    results = []
    urls_to_try = []
    if check_https:
        urls_to_try.append(f"https://{domain}")
    if check_http:
        urls_to_try.append(f"http://{domain}")

    for url in urls_to_try:
        try:
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=True,
            )
            # Considérer comme site vivant si status 2xx, 3xx, ou même 401/403 (existe)
            is_alive = resp.status_code < 500 or resp.status_code in (401, 403, 405, 407)
            # Extraire titre si HTML
            title = None
            if "text/html" in resp.headers.get("Content-Type", ""):
                try:
                    text = resp.text[:5000]
                    # Regex titre simple
                    import re
                    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()[:200]
                        # Nettoyer whitespace
                        title = " ".join(title.split())
                except Exception:
                    pass

            results.append({
                "url": url,
                "final_url": resp.url,
                "status": resp.status_code,
                "alive": is_alive,
                "title": title,
                "server": resp.headers.get("Server"),
                "content_type": resp.headers.get("Content-Type"),
                "content_length": resp.headers.get("Content-Length"),
                "https": url.startswith("https://"),
            })
            if is_alive:
                # Si https marche, pas besoin de tester http (sauf si on veut les deux)
                # Mais on continue pour info
                pass

        except requests.exceptions.SSLError:
            # Retry sans vérification SSL
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=follow_redirects, verify=False)
                is_alive = resp.status_code < 500 or resp.status_code in (401, 403, 405)
                results.append({
                    "url": url,
                    "final_url": resp.url,
                    "status": resp.status_code,
                    "alive": is_alive,
                    "title": None,
                    "server": resp.headers.get("Server"),
                    "content_type": resp.headers.get("Content-Type"),
                    "ssl_error": True,
                    "https": url.startswith("https://"),
                })
            except Exception as e:
                results.append({"url": url, "alive": False, "error": str(e), "https": url.startswith("https://")})
        except Exception as e:
            results.append({"url": url, "alive": False, "error": str(e), "https": url.startswith("https://")})

    # Synthèse
    alive_any = any(r.get("alive") for r in results)
    best = None
    for r in results:
        if r.get("alive"):
            best = r
            break
    if not best and results:
        best = results[0]

    return {
        "domain": domain,
        "alive": alive_any,
        "best": best,
        "all_attempts": results,
    }


def bulk_check(
    domains: list[str],
    max_workers: int = 20,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, dict]:
    """
    Vérifie en masse une liste de domaines
    Retourne dict domaine -> check_result
    """
    results: dict[str, dict] = {}

    def _check_one(d: str):
        return d, check_website(d, timeout=timeout)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_one, d): d for d in domains}
        for fut in as_completed(futures):
            d, res = fut.result()
            results[d] = res

    return results


def filter_alive(domains: list[str], max_workers: int = 20, timeout: int = 5) -> list[str]:
    """Retourne seulement les domaines avec site web vivant"""
    checks = bulk_check(domains, max_workers=max_workers, timeout=timeout)
    return [d for d, r in checks.items() if r.get("alive")]
