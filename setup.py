from setuptools import setup, find_packages

setup(
    name="dns-crawl",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "dnspython>=2.4.0",
        "requests>=2.31.0",
        "rich>=13.0.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "dns-crawl=dns_crawl.cli:main",
            "dns_crawl=dns_crawl.cli:main",
        ],
    },
    python_requires=">=3.9",
)
