"""
Exemple complet commenté en français
"""
from dns_crawl import DnsCrawler, CrawlConfig

# Configuration: on veut TOUT (le plus exhaustif)
config = CrawlConfig(
    # Techniques
    do_resolve_all=True,       # Enregistrements DNS classiques
    do_zone_transfer=True,     # Tente AXFR (rarement autorisé mais puissant)
    do_ct_logs=True,           # Certificats Let's Encrypt / CT logs (très efficace)
    do_bruteforce=True,        # Dictionnaire (200 sous-domaines par défaut)
    do_reverse_ip=True,        # Reverse IP/NS (trouver tous les domaines sur même serveur)
    do_web_check=False,        # Vérifier si site répond en HTTP (optionnel, plus lent)

    # Paramètres
    wordlist="common",         # "top100", "common", "large" ou chemin fichier
    bruteforce_workers=50,      # Nombre de threads
    dns_timeout=3.0,
    reverse_sources=["hackertarget", "rapiddns", "ptr"],
)

crawler = DnsCrawler(config=config)

# --- Cas 1: Tu as un domaine (ex: monsite.fr) et tu veux ses sous-domaines ---
result = crawler.crawl("example.com")
print(f"Domaines trouvés: {result.all_domains}")
print(f"Sites web: {result.all_websites}")

# Sauvegarde
from dns_crawl.export import Exporter
Exporter.to_json(result, "resultats_example.json")
Exporter.to_txt(result, "resultats_example.txt")  # un domaine par ligne

# --- Cas 2: Tu as un serveur DNS (ex: ns1.hebergeur.com) et tu veux tous les sites dessus ---
# C'est le cas "crawler des dns"
result_ns = crawler.crawl("ns1.ovh.net")
print(f"Sites hébergés sur ns1.ovh.net: {result_ns.all_domains}")

# --- Cas 3: Tu as une IP d'hébergeur ---
result_ip = crawler.crawl("8.8.8.8")
print(f"Sites sur IP 8.8.8.8: {result_ip.reverse_ptr}")

# --- Cas 4: Plage IP ---
result_cidr = crawler.crawl("192.168.1.0/24")
print(f"Sites sur 192.168.1.0/24: {result_cidr.reverse_ptr}")
