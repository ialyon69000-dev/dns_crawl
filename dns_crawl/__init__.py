"""
dns_crawl - Crawler DNS pour énumérer tous les sites webs référencés sur un DNS.

Ce package permet de crawler un DNS / domaine pour obtenir :
- Tous les enregistrements DNS (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, etc.)
- Tous les sous-domaines (via bruteforce, Certificate Transparency, zone transfer)
- Tous les domaines hébergés sur un même serveur DNS / NS
- Le reverse DNS sur une plage IP

Auteur: dns_crawl
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "dns_crawl"

from .crawler import DnsCrawler, CrawlResult, CrawlConfig
from .resolver import DnsResolver

__all__ = ["DnsCrawler", "CrawlResult", "CrawlConfig", "DnsResolver"]
