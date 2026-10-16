.PHONY: install test lint crawl demo web clean

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v
	python tests/test_resolver.py
	python tests/test_crawler.py

lint:
	python -m py_compile dns_crawl/*.py
	python -m py_compile dns_crawl/web/*.py

crawl:
	@echo "Exemple: make crawl DOMAIN=example.com"
	@if [ -z "$(DOMAIN)" ]; then echo "Usage: make crawl DOMAIN=example.com"; exit 1; fi
	dns-crawl $(DOMAIN) -o output/$(DOMAIN).json --format json

demo:
	python examples/demo.py

web:
	uvicorn dns_crawl.web.app:app --host 0.0.0.0 --port 8000 --reload

clean:
	rm -rf __pycache__ .pytest_cache dist build *.egg-info
	rm -rf output/* resultats*
	find . -name "*.pyc" -delete
