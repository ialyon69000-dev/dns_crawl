"""Test d'intégration du crawler avec mock DNS si possible"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import patch, MagicMock

def test_crawler_no_network():
    """Teste le crawler avec DNS mocké pour ne pas dépendre du réseau"""
    from dns_crawl.crawler import DnsCrawler, CrawlConfig
    from dns_crawl.resolver import DnsResolver

    config = CrawlConfig(
        do_resolve_all=True,
        do_zone_transfer=False,
        do_ct_logs=False,
        do_bruteforce=False,
        do_reverse_ip=False,
        do_web_check=False,
    )
    crawler = DnsCrawler(config=config)

    # Mock resolver pour simuler un domaine
    mock_records = {
        "A": ["93.184.216.34"],
        "NS": ["ns1.example.com."],
        "MX": ["10 mail.example.com."],
        "TXT": ["v=spf1 -all"],
    }

    with patch.object(DnsResolver, 'resolve_all', return_value=mock_records):
        with patch.object(DnsResolver, 'get_ns', return_value=["ns1.example.com"]):
            with patch.object(DnsResolver, 'get_authoritative_ns_ips', return_value={"ns1.example.com": ["93.184.216.34"]}):
                result = crawler.crawl("example.com")
                assert result.target == "example.com"
                assert result.normalized == "example.com"
                assert result.dns_records == mock_records
                assert result.duration >= 0

    print("✓ crawler no-network test passed")

def test_cidr_mock():
    from dns_crawl.crawler import DnsCrawler, CrawlConfig
    config = CrawlConfig(do_reverse_ip=False)
    crawler = DnsCrawler(config=config)
    # Mock reverse
    with patch("dns_crawl.crawler.reverse_ptr_range") as mock_ptr:
        mock_ptr.return_value = {"success": True, "domains": ["ptr.example.com"], "results": [], "count": 1, "ips_scanned": 1}
        result = crawler.crawl("8.8.8.8")
        assert result.target_type == "ip"
        assert "ptr.example.com" in result.all_domains
    print("✓ cidr mock test passed")

if __name__ == "__main__":
    test_crawler_no_network()
    test_cidr_mock()
    print("✓ All crawler tests passed")
