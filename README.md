# 🔍 DNS Crawl — Trouve tous les sites webs référencés sur un DNS

Outil OSINT en Python pour **crawler un DNS** et énumérer **tous les sites/domaine hébergés dessus**.

> Tu donnes un **domaine**, un **serveur DNS (NS)**, une **IP** ou une **plage CIDR** → il te renvoie tous les sites webs référencés.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![dnspython](https://img.shields.io/badge/dnspython-2.9-orange.svg)](https://pypi.org/project/dnspython/)

---

## ✨ Qu'est-ce que ça fait ?

| Ta cible | Ce qu'il trouve |
|----------|-----------------|
| `example.com` | Tous les sous-domaines & sites (`www`, `api`, `mail`, `vpn`...) + enregistrements DNS |
| `ns1.ovh.net` | **Tous les domaines hébergés sur ce serveur DNS** (reverse NS) |
| `8.8.8.8` | Tous les sites sur cette IP (reverse PTR + reverse IP OSINT) |
| `1.1.1.0/24` | Tous les PTR d'une plage réseau |

### Techniques combinées

- **📋 Enregistrements DNS** — A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA (via `dnspython`)
- **🔓 Zone Transfer (AXFR)** — Tente de récupérer toute la zone si mal configuré (jackpot)
- **🔐 Certificate Transparency (crt.sh)** — Tous les domaines ayant eu un certificat TLS (très efficace)
- **🔨 Bruteforce dictionnaire** — ~200 sous-domaines par défaut, wordlists `top100`/`common`/`large` ou custom
- **🔄 Reverse IP / Reverse NS** — Trouve tous les domaines sur même IP ou même NS (via Hackertarget, Rapiddns)
- **🌐 Vérification Web** — Optionnel: teste HTTP/HTTPS pour filtrer les vrais sites
- **⚡ Parallélisé** — Threads, wildcard detection, cache DNS

---

## 🚀 Installation

```bash
git clone https://github.com/ialyon69000-dev/dns_crawl.git
cd dns_crawl
pip install -r requirements.txt
# ou
pip install -e .
```

**Dépendances:** `dnspython`, `requests`, `rich`, `aiohttp` — rien d'autre.

---

## ⚡ Utilisation rapide

### CLI (recommandé)

```bash
# 1. Tous les sous-domaines / sites d'un domaine
dns-crawl example.com

# 2. Tous les sites hébergés sur un serveur DNS
dns-crawl ns1.ovh.net --reverse

# 3. Tous les sites sur une IP
dns-crawl 8.8.8.8 --reverse
dns-crawl 192.168.1.0/24

# 4. Exporter
dns-crawl example.com -o resultats.json
dns-crawl example.com -o resultats.txt --format txt
dns-crawl example.com -o out --format json,csv,txt   # multi-format

# 5. Options avancées
dns-crawl example.com --wordlist large --workers 80
dns-crawl example.com --wordlist wordlists/monfichier.txt
dns-crawl example.com --wordlist www,mail,api,admin
dns-crawl example.com --web-check          # vérifie HTTP
dns-crawl example.com --no-ct --no-bruteforce   # minimal
dns-crawl example.com --resolvers 1.1.1.1,8.8.8.8

# 6. Aide
dns-crawl --help
dns-crawl --list-wordlists
```

**Sortie CLI** (avec `rich`):
```
╔═══════════════════════════════════════╗
║         D N S   C R A W L  v1.0.0   ║
║  Énumère tous les sites sur un DNS  ║
╚═══════════════════════════════════════╝

Cible: example.com (domain)
Techniques: DNS=oui | CT=oui | Bruteforce=oui | AXFR=oui

✓ Crawl terminé (12.34s)
Total domaines/sites uniques: 42
...

🌐 Tous les sites / domaines trouvés (42)
• api.example.com         https://api.example.com
• www.example.com         https://www.example.com
• vpn.example.com         https://vpn.example.com
...
```

### Python (librairie)

```python
from dns_crawl import DnsCrawler, CrawlConfig

# Config simple
crawler = DnsCrawler()
result = crawler.crawl("example.com")

print(result.all_domains)   # ['api.example.com', 'www.example.com', ...]
print(result.all_websites)  # ['https://api.example.com', ...]
print(result.count)         # 42
print(result.summary())

# Export
from dns_crawl.export import Exporter
Exporter.to_json(result, "result.json")
Exporter.to_txt(result, "result.txt")   # un domaine par ligne
Exporter.to_csv(result, "result.csv")

# Config avancée: tout activer
config = CrawlConfig(
    do_resolve_all=True,
    do_zone_transfer=True,
    do_ct_logs=True,
    do_bruteforce=True,
    do_reverse_ip=True,      # trouver tous les domaines sur même NS/IP
    do_web_check=True,       # vérifier HTTP
    wordlist="large",        # ou chemin / liste inline
    bruteforce_workers=80,
)
crawler = DnsCrawler(config=config)
result = crawler.crawl("ns1.hebergeur.com")  # tous les sites sur ce NS
```

### Zone entière (ex: .ru, .fr) — Énumérer tous les NS d'une zone

Nouveau : crawl d'une **zone TLD complète** (ex: `.ru` = 5M+ domaines) pour obtenir **tous les serveurs DNS qui hébergent du .ru**, puis les crawler à leur tour.

```bash
# 1. Voir les NS officiels du TLD .ru lui-même (6 serveurs, ultra rapide)
dns-crawl --tld-info --zone ru

# 2. Énumérer TOUS les NS utilisés par des domaines .ru (nécessite une liste)
#    a) Depuis un fichier que tu as (whois dump, export, etc.)
dns-crawl --zone ru --input-list domaines_ru.txt --limit 5000 -o ns_zone_ru.json

#    b) Depuis CT logs (tente de récupérer via crt.sh, limité par API)
dns-crawl --zone ru --sources crt.sh --limit 2000 -o ns_zone_ru.json

# 3. Crawler chaque NS trouvé (tous les sites sur chaque NS) — mode lourd
dns-crawl --zone ru --input-list domaines_ru.txt --crawl-ns --limit 100 -o crawl_zone_ru.json
```

**Python :**
```python
from dns_crawl.zone_enum import get_tld_nameservers, crawl_ns_zone, crawl_all_ns

# NS du TLD .ru lui-même
tld = get_tld_nameservers("ru")  # 6 serveurs: a.dns.ripn.net ...

# Tous les NS hébergeant du .ru (à partir d'une liste de domaines)
zone = crawl_ns_zone(tld="ru", input_file="domaines_ru.txt", limit=50000)
print(zone["summary"])  # Zone .ru: 50000 domaines → 1843 NS uniques
print(zone["ns_enumeration"]["top_ns"][:5])  # top 5 hébergeurs .ru

# Crawler les 50 plus gros NS
results = crawl_all_ns(zone["ns_enumeration"]["ns_list"][:50])
```

> **Comment obtenir la liste des domaines .ru ?**
> - **Idéal** : dump NIC.ru / whois si tu as accès
> - **OSINT** : `crt.sh` → `%.ru`, Tranco top 1M filtré `.ru`, CommonCrawl
> - **Fichier** : `cat domaines.txt | dns-crawl --zone ru --input-list -`
> - Le tool gère `--limit` pour tester progressivement (ne pas inonder le .ru en une fois)

### Interface Web (optionnelle)

```bash
pip install fastapi uvicorn
uvicorn dns_crawl.web.app:app --host 0.0.0.0 --port 8000

# Ouvre http://localhost:8000
```

Interface avec champ de saisie, cases à cocher pour chaque technique, résultats en temps réel, export TXT/JSON.

---

## 📂 Structure du projet

```
dns_crawl/
├── dns_crawl/
│   ├── __init__.py       # Exports publics
│   ├── __main__.py       # python -m dns_crawl
│   ├── cli.py            # CLI rich + argparse (+ --zone)
│   ├── crawler.py        # Orchestrateur principal (DnsCrawler)
│   ├── resolver.py       # Wrapper dnspython (multi-resolvers, cache, wildcard)
│   ├── zone_enum.py      # Énumération zone TLD (.ru, .fr) → tous les NS
│   ├── zone_transfer.py  # AXFR
│   ├── ct_logs.py        # Certificate Transparency via crt.sh
│   ├── bruteforce.py     # Bruteforce dictionnaire + wildcard filtering
│   ├── reverse.py        # PTR + reverse IP (Hackertarget, Rapiddns)
│   ├── web_check.py      # Vérification HTTP/HTTPS
│   ├── export.py         # JSON / TXT / CSV / hosts
│   ├── utils.py          # Normalisation, détection type cible
│   └── web/
│       └── app.py        # FastAPI UI
├── wordlists/
│   ├── subdomains-top100.txt   # Top 100
│   ├── subdomains-common.txt   # ~200 (défaut)
│   └── subdomains-large.txt    # ~500+ (exhaustif)
├── examples/
│   ├── demo.py
│   └── exemple_complet.py
├── tests/
│   ├── test_resolver.py
│   └── test_crawler.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 📖 Détails des techniques

### 1. DNS records
Interroge `A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA` sur le domaine principal. Utilise plusieurs résolveurs (Cloudflare, Google, Quad9) avec fallback et cache.

### 2. Zone Transfer (AXFR)
Tente `dns.query.xfr` sur chaque NS autoritaire. Si le serveur est mal configuré (ouvert), on récupère **toute la zone** = tous les domaines en une fois. Rare mais jackpot quand ça marche.

```python
from dns_crawl.zone_transfer import attempt_zone_transfer
zt = attempt_zone_transfer("example.com")
if zt["success"]:
    print(zt["records"])
```

### 3. Certificate Transparency (crt.sh)
Interroge `https://crt.sh/?q=%.example.com&output=json` — chaque certificat TLS émis est loggué publiquement. C'est la méthode la plus efficace pour trouver des sous-domaines sans bruteforce.

### 4. Bruteforce dictionnaire
Teste chaque entrée de la wordlist (`label.example.com`) en parallèle (50 threads). Détecte et filtre les **wildcards** (`*.example.com`) pour éviter les faux positifs.

```bash
dns-crawl example.com --wordlist large --workers 100
```

### 5. Reverse IP / Reverse NS (tous les sites sur un DNS)
Le cas **principal** de ta demande: *« tous les sites webs référencés sur un DNS »*.

- **Reverse NS**: donné `ns1.hebergeur.com`, trouve tous les domaines ayant `NS = ns1.hebergeur.com` via Rapiddns/ViewDNS.
- **Reverse IP**: donné `8.8.8.8`, trouve tous les domaines sur cette IP via Hackertarget + PTR.

```bash
dns-crawl ns1.ovh.net --reverse     # tous les domaines chez OVH sur ce NS
dns-crawl 8.8.8.8 --reverse          # tous les vhosts sur cette IP
```

> ⚠️ Les APIs OSINT gratuites sont rate-limitées ; le tool fait des pauses et try plusieurs sources.

### 6. Vérification Web
Teste `https://` puis `http://` sur chaque domaine trouvé. Utile pour filtrer les entrées DNS sans site web.

```bash
dns-crawl example.com --web-check
```

---

## 🧪 Tests

```bash
pytest tests/ -v
# ou sans pytest
python tests/test_resolver.py
python tests/test_crawler.py
```

---

## ⚠️ Notes légales & éthiques

- Ce tool est pour **OSINT défensif**, audit de son propre infra, bug bounty autorisé, recherche.
- Respecte le **rate limiting** (le tool ajoute des pauses, utilise plusieurs résolveurs).
- Ne pas utiliser pour harceler, DoS bruteforce massif. Le bruteforce par défaut est raisonnable (~200 requêtes).
- Certaines APIs (crt.sh, Hackertarget) sont publiques et gratuites ; leur usage intensif peut être bloqué — le tool gère les retries.

---

## 🛠️ TODO / Roadmap

- [ ] Support DNSSEC / DoH (DNS over HTTPS) pour résoudre via Cloudflare/Google DoH
- [ ] Passive DNS (VirusTotal, SecurityTrails) avec clé API optionnelle
- [ ] Sortie HTML interactive
- [ ] Scan de ports léger (80/443) en plus du check HTTP
- [ ] Mode “discovery” récursif (crawler les sous-domaines trouvés)

---

## 📜 Licence

MIT — Fais-en ce que tu veux, attribution appréciée.

---

## 🤝 Contribuer

PR welcome ! Ouvre une issue si tu veux ajouter une source OSINT.

**Auteur:** `ialyon69000-dev` — Lyon, FR ⚡

> *Crawler des DNS pour obtenir tous les sites webs référencés dessus — enfin simple.*
