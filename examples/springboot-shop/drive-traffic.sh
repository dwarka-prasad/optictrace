#!/usr/bin/env bash
# Drives realistic traffic through the shop so the dashboard has something to
# show: several tenants, a mix of routes, and enough failures to make the
# error rate and the tail-sampling rules meaningful.
set -u
BASE=${BASE:-http://127.0.0.1:8080}
N=${1:-60}

TENANTS=(acme globex initech hooli)
REGIONS=(ap-south-1 us-east-1 eu-west-1)
PLANS=(free growth enterprise)
SKUS=(SKU-100 SKU-200 SKU-300 SKU-400 SKU-999)

hdr() {
  local t=${TENANTS[$((RANDOM % ${#TENANTS[@]}))]}
  local r=${REGIONS[$((RANDOM % ${#REGIONS[@]}))]}
  local p=${PLANS[$((RANDOM % ${#PLANS[@]}))]}
  printf -- "-H X-Tenant-ID:%s -H X-Region:%s -H X-Plan:%s" "$t" "$r" "$p"
}

for i in $(seq 1 "$N"); do
  sku=${SKUS[$((RANDOM % ${#SKUS[@]}))]}
  h=$(hdr)
  case $((RANDOM % 10)) in
    0|1|2|3)
      # Checkout: three spans per call, and the only route carrying card data.
      qty=$((RANDOM % 4 + 1))
      curl -s -o /dev/null $h \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer sk_live_do_not_log_me' \
        -X POST "$BASE/api/v1/orders?channel=web" \
        -d "{\"sku\":\"$sku\",\"qty\":$qty,\"customer\":{\"name\":\"Test $i\",\"email\":\"buyer$i@example.com\",\"phone\":\"+91-90000000$((i % 100))\"},\"card\":{\"number\":\"4111111111111111\",\"cvv\":\"312\",\"holder\":\"TEST BUYER\"}}"
      ;;
    4|5|6|7)
      curl -s -o /dev/null $h "$BASE/api/v1/catalog/$sku"
      ;;
    8)
      curl -s -o /dev/null $h -H 'Content-Type: application/json' \
        -X POST "$BASE/api/v1/auth/login" \
        -d '{"username":"buyer","password":"hunter2"}'
      ;;
    9)
      curl -s -o /dev/null "$BASE/api/v1/health"
      ;;
  esac
done
echo "sent $N requests to $BASE"
