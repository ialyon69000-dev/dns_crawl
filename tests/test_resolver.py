"""Tests basiques - ne nécessitent pas réseau si mocké, mais on teste l'import"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    from dns_crawl import DnsCrawler, CrawlConfig, DnsResolver
    from dns_crawl.utils import normalize_target, detect_target_type, clean_domain_list
    assert True

def test_normalize():
    from dns_crawl.utils import normalize_target
    assert normalize_target("https://example.com/path") == "example.com"
    assert normalize_target("EXAMPLE.COM.") == "example.com"
    assert normalize_target("sub.example.com:8080") == "sub.example.com"

def test_detect_type():
    from dns_crawl.utils import detect_target_type
    assert detect_target_type("example.com") == "domain"
    assert detect_target_type("ns1.ovh.net") == "ns"
    assert detect_target_type("8.8.8.8") == "ip"
    assert detect_target_type("192.168.1.0/24") == "cidr"

def test_clean():
    from dns_crawl.utils import clean_domain_list
    lst = ["*.Example.COM.", "www.example.com", "www.example.com", "", "BAD"]
    cleaned = clean_domain_list(lst)
    assert "example.com" in cleaned
    assert "www.example.com" in cleaned
    assert len(cleaned) == 2

def test_crawl_result():
    from dns_crawl.crawler import CrawlResult
    r = CrawlResult(target="example.com", target_type="domain", normalized="example.com", started_at=0, finished_at=1, duration=1, all_domains=["a.example.com"])
    assert r.count == 1
    assert "example.com" in r.summary().lower() or "Cible" in r.summary()

def test_wordlist():
    from dns_crawl.bruteforce import get_wordlist
    wl = get_wordlist(None)
    assert len(wl) > 50
    assert "www" in wl
    wl2 = get_wordlist("www,mail,api")
    assert wl2 == ["www", "mail", "api"]

if __name__ == "__main__":
    test_imports()
    test_normalize()
    test_detect_type()
    test_clean()
    test_crawl_result()
    test_wordlist()
    print("✓ All tests passed")
