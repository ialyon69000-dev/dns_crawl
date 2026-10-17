"""
Exemple: Énumérer tous les serveurs DNS d'une zone .ru puis les crawler
"""
from dns_crawl.zone_enum import get_tld_nameservers, crawl_ns_zone, crawl_all_ns
from dns_crawl.resolver import DnsResolver

# 1. Les NS officiels du TLD .ru lui-même (rapide, ~6 serveurs)
print("=== 1. NS autoritaires du TLD .ru ===")
tld_info = get_tld_nameservers("ru")
print(f"TLD .ru géré par {tld_info['ns_count']} serveurs:")
for ns in tld_info["ns_hosts"]:
    print(f"  - {ns} → {tld_info['details'][ns]['ips']}")

# 2. Tous les NS hébergeant des domaines .ru (nécessite une liste de domaines)
# Option A: depuis un fichier que vous avez (recommandé pour .ru qui a 5M+ domaines)
# Exemple: obtenir liste via https://github.com/torvalds/linux? Non, pour .ru:
# - Tranco, CT logs, ou dump whois
print("\n=== 2. Tous les NS utilisés par des domaines .ru ===")
# Exemple avec fichier local:
# zone = crawl_ns_zone(tld="ru", input_file="domaines_ru.txt", limit=5000)
# print(zone["summary"])
# print(f"Top NS: {zone['ns_enumeration']['top_ns'][:5]}")

# Démo avec petit échantillon fictif (pour tester sans gros fichier)
echantillon = [
    "yandex.ru", "mail.ru", "vk.com", "ok.ru", "avito.ru",
    "lenta.ru", "rambler.ru", "gosuslugi.ru", "sberbank.ru", "wildberries.ru"
]
# On force tld="ru" mais on passe directement la liste
zone = crawl_ns_zone(tld="ru", domains=echantillon, limit=10)
print(f"{zone['summary']}")
print(f"NS uniques: {zone['ns_enumeration']['ns_count']}")
for ns, cnt in zone["ns_enumeration"]["top_ns"]:
    print(f"  {ns}: {cnt} domaines ({zone['ns_details'].get(ns, {}).get('percent','?')}%)")

# 3. Crawler chaque NS trouvé (tous les sites dessus)
print("\n=== 3. Crawler chaque NS (reverse) ===")
# Attention: lourd si milliers de NS. On limite à 3 pour demo.
if zone["ns_enumeration"]["ns_list"]:
    top3 = zone["ns_enumeration"]["ns_list"][:3]
    crawl_results = crawl_all_ns(top3, max_workers=5)
    for ns, data in crawl_results["per_ns"].items():
        print(f"NS {ns}: {data.get('count', 0)} sites")
    print(f"Total unique across 3 NS: {crawl_results['total_unique_domains_across_all_ns']}")

# 4. Workflow complet recommandé pour .ru en production
print("""
=== Workflow .ru complet (production) ===
# 1. Obtenir liste domaines .ru (choisir une source)
#    - Depuis CT: dns-crawl --zone ru --sources crt.sh --limit 10000 -o zone_ru.json
#    - Depuis fichier: whois/nic.ru dump → domaines_ru.txt

# 2. Énumérer NS
# dns-crawl --zone ru --input-list domaines_ru.txt --limit 50000 -o ns_zone_ru.json
# → donne liste de tous les NS (ex: 2000 NS uniques)

# 3. Crawler chaque NS (tous les sites sur chaque NS)
# dns-crawl --zone ru --input-list domaines_ru.txt --crawl-ns --limit 100 -o crawl_ru.json
# → pour les 100 top NS, lance reverse et récupère tous les sites dessus

# En Python:
# zone = crawl_ns_zone(tld="ru", input_file="domaines_ru.txt", limit=50000)
# crawl_all_ns(zone['ns_enumeration']['ns_list'], limit_ns=50)
""")
