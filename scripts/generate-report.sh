HOST="${1:-$(hostname)}"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
FILENAME="report-${HOST}-${DATE}.json"

mkdir -p reports/

sudo trivy rootfs \
  --scanners vuln / \
  --skip-dirs /zfs_mirror01,/proc,/sys,/dev,/run \
  --format json \
  -o "reports/$FILENAME"

# Regenerate index.json with all report files
ls reports/report-*.json 2>/dev/null | sed 's/.*\///' | jq -R -s 'split("\n") | map(select(length > 0))' > reports/index.json
