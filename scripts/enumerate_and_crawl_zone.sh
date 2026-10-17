#!/usr/bin/env bash
# Workflow complet pour énumérer et crawler une zone (ex: .ru)
# Usage: ./scripts/enumerate_and_crawl_zone.sh ru 50000
set -e

TLD="${1:-ru}"
LIMIT="${2:-50000}"
OUTPUT_DIR="output/zone_${TLD}"

echo "╔══════════════════════════════════════════════╗"
echo "║ Crawling zone .${TLD} (limit ${LIMIT})      ║"
echo "╚══════════════════════════════════════════════╝"
echo "Output dir: ${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# 1. Générer liste domaines
echo ""
echo "▶ 1/3 Génération liste domaines .${TLD}..."
python scripts/generate_zone_list.py --tld "${TLD}" --output "${OUTPUT_DIR}/domaines_${TLD}.txt" --sources crt.sh,tranco --limit "${LIMIT}"

# 2. Énumérer tous les NS de la zone
echo ""
echo "▶ 2/3 Énumération des serveurs DNS de la zone .${TLD}..."
dns-crawl --zone "${TLD}" --input-list "${OUTPUT_DIR}/domaines_${TLD}.txt" --limit "${LIMIT}" -o "${OUTPUT_DIR}/ns_zone_${TLD}.json"
# Aussi exporter liste simple
dns-crawl --zone "${TLD}" --input-list "${OUTPUT_DIR}/domaines_${TLD}.txt" -o "${OUTPUT_DIR}/ns_zone_${TLD}.txt" --limit "${LIMIT}" 2>&1 | tail -5

# 3. (Optionnel) Crawler les top 100 NS - décommentez si vous voulez aller au bout
# echo ""
# echo "▶ 3/3 Crawling de chaque NS (reverse)..."
# dns-crawl --zone "${TLD}" --input-list "${OUTPUT_DIR}/domaines_${TLD}.txt" --crawl-ns --limit 100 -o "${OUTPUT_DIR}/crawl_${TLD}.json"

echo ""
echo "✓ Terminé. Fichiers dans ${OUTPUT_DIR}/ :"
ls -lh "${OUTPUT_DIR}/"
echo ""
echo "Pour crawler tous les sites sur chaque NS (lourd):"
echo "  dns-crawl --zone ${TLD} --input-list ${OUTPUT_DIR}/domaines_${TLD}.txt --crawl-ns --limit 100 -o ${OUTPUT_DIR}/crawl_${TLD}.json"
