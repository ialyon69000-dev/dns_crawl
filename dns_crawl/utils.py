"""Fonctions utilitaires"""
import re
import ipaddress
import socket
from typing import Union
from urllib.parse import urlparse

# Regex domaine
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
# Regex sous-domaine simple
SUBDOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9\-\.\*]+$")


def is_ip(target: str) -> bool:
    """Vérifie si la cible est une IP v4/v6"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_cidr(target: str) -> bool:
    """Vérifie si c'est un CIDR (ex: 192.168.1.0/24)"""
    try:
        ipaddress.ip_network(target, strict=False)
        return "/" in target
    except ValueError:
        return False


def is_domain(target: str) -> bool:
    """Vérifie si c'est un domaine valide"""
    target = target.strip().lower().rstrip(".")
    # Enlever le port si présent
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
    return bool(DOMAIN_REGEX.match(target))


def normalize_target(target: str) -> str:
    """
    Normalise une cible entrée par l'utilisateur.
    Accepte: domaine, URL, IP, CIDR, host:port
    Retourne: domaine / IP nettoyé
    """
    target = target.strip()
    # Si c'est une URL, extraire le hostname
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        host = parsed.hostname or target
        return host.lower().rstrip(".")

    # Enlever le schéma obscur (ex: //example.com)
    if target.startswith("//"):
        parsed = urlparse("https:" + target)
        if parsed.hostname:
            return parsed.hostname.lower().rstrip(".")

    # Enlever port
    # Gérer [IPv6]:port et host:port
    if target.startswith("["):
        # IPv6 bracket
        end = target.find("]")
        if end != -1:
            return target[1:end].lower()

    # host:port simple (ne pas confondre avec IPv6 sans brackets - rare)
    if target.count(":") == 1 and not is_ip(target):
        # potentiel host:port
        host_part = target.split(":")[0]
        if is_domain(host_part) or is_ip(host_part):
            return host_part.lower().rstrip(".")

    return target.lower().rstrip(".").rstrip("/")


def detect_target_type(target: str) -> str:
    """
    Détecte le type de cible:
    - 'ip' : adresse IP unique
    - 'cidr' : plage réseau
    - 'ns' : ressemble à un nameserver (ns1.*, dns.*, etc.) mais reste un domaine
    - 'domain' : domaine standard

    Note: 'ns' est un sous-cas de 'domain', mais on le signale pour activer
    les recherches reverse-NS spécifiques.
    """
    t = normalize_target(target)

    if is_cidr(t):
        return "cidr"
    if is_ip(t):
        return "ip"
    if is_domain(t):
        # Heuristique NS: commence par ns, dns, nsd, auth, etc.
        label = t.split(".")[0].lower()
        ns_prefixes = ("ns", "dns", "nsd", "auth", "pdns", "powerdns")
        if any(label.startswith(p) for p in ns_prefixes):
            # Vérifier qu'il a au moins 2 labels (ns1.example.com)
            if t.count(".") >= 2:
                return "ns"
            # ns1.example.com => ns, maisexample.com seul avec label ns? non
        return "domain"
    return "unknown"


def is_nameserver_hostname(host: str) -> bool:
    return detect_target_type(host) == "ns"


def clean_domain_list(domains: list[str]) -> list[str]:
    """Nettoie et déduplique une liste de domaines"""
    seen = set()
    cleaned = []
    for d in domains:
        if not d:
            continue
        d = d.strip().lower().rstrip(".").lstrip("*.").lstrip(".")
        # Enlever port / path
        if "/" in d:
            d = d.split("/")[0]
        if ":" in d and d.count(":") == 1:
            d = d.split(":")[0]
        if not d or d in seen:
            continue
        # Filtrer les entrées invalides (trop court, pas de point, etc.)
        if "." not in d:
            continue
        if len(d) < 4:
            continue
        # Exclure les emails mal parsés
        if "@" in d:
            d = d.split("@")[-1]
        seen.add(d)
        cleaned.append(d)
    return sorted(cleaned)


def chunks(lst: list, n: int):
    """Découpe une liste en chunks de taille n"""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def sanitize_filename(name: str) -> str:
    """Pour exports"""
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)
