HOST="${1:-$(hostname)}"
DATE="$(date +%F)"
FILENAME="report-${HOST}-${DATE}.json"

mkdir -p reports/

sudo trivy rootfs \
  --scanners vuln / \
  --skip-dirs /zfs_mirror01,/proc,/sys,/dev,/run \
  --format json \
  -o reports/$FILENAME
