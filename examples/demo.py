"""
Exemples d'utilisation du crawler DNS en Python
"""
from dns_crawl.crawler import DnsCrawler, CrawlConfig

# Exemple 1: Crawl simple d'un domaine (toutes techniques par défaut)
print("=== Exemple 1: Crawl simple ===")
crawler = DnsCrawler()
result = crawler.crawl("example.com")
print(f"Trouvé {result.count} domaines: {result.all_domains[:5]}")
print(result.summary())

# Exemple 2: Avec reverse NS (trouver tous les sites sur un NS)
print("\n=== Exemple 2: Reverse NS ===")
config = CrawlConfig(
    do_bruteforce=False,  # désactiver bruteforce pour aller vite
    do_reverse_ip=True,   # activer reverse
    do_ct_logs=True,
)
crawler2 = DnsCrawler(config=config)
result2 = crawler2.crawl("ns1.ovh.net")  # ou un NS
print(f"Domaines sur ns1.ovh.net: {result2.count}")
print(result2.all_domains[:10])

# Exemple 3: Bruteforce avec wordlist custom
print("\n=== Exemple 3: Bruteforce custom ===")
config3 = CrawlConfig(
    wordlist=["www", "api", "admin", "dev", "staging", "vpn"],  # liste inline
    do_ct_logs=False,
    do_reverse_ip=False,
)
crawler3 = DnsCrawler(config=config3)
result3 = crawler3.crawl("example.com")
print(result3.bruteforce)

# Exemple 4: IP / CIDR (reverse PTR)
print("\n=== Exemple 4: Reverse PTR sur IP ===")
result4 = crawler.crawl("8.8.8.8")
print(result4.reverse_ptr)

# Exemple 5: Export
print("\n=== Exemple 5: Export ===")
from dns_crawl.export import Exporter
Exporter.to_json(result, "output/example.json")
Exporter.to_txt(result, "output/example.txt")
Exporter.to_csv(result, "output/example.csv")
print("Exporté vers output/")

# Exemple 6: Crawl multiple
print("\n=== Exemple 6: Crawl multiple ===")
results = crawler.crawl_many(["example.com", "google.com"])
for target, res in results.items():
    print(f"{target}: {res.count} domaines")
