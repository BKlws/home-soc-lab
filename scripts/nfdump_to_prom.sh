#!/usr/bin/env bash
set -euo pipefail

OUT="/var/lib/node_exporter/textfile_collector/netflow.prom"
TMP="$(mktemp)"

ASN_DB="/var/lib/GeoIP/GeoLite2-ASN.mmdb"
COUNTRY_DB="/var/lib/GeoIP/GeoLite2-Country.mmdb"
FLOW_DIR="/var/cache/nfdump"

escape_label() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

ip_to_asn() {
  local ip="$1"
  mmdblookup --file "$ASN_DB" --ip "$ip" 2>/dev/null | awk '
    /"autonomous_system_number":/ {
      getline
      gsub(/[^0-9]/, "", $0)
      asn=$0
    }
    /"autonomous_system_organization":/ {
      getline
      gsub(/^[[:space:]]*"/, "", $0)
      sub(/".*/, "", $0)
      org=$0
    }
    END {
      if (asn != "") {
        if (org == "") org="UNKNOWN"
        print "AS" asn " " org
      }
    }'
}

ip_to_country() {
  local ip="$1"
  mmdblookup --file "$COUNTRY_DB" --ip "$ip" 2>/dev/null | awk '
    /"country":/ { incountry=1; next }
    incountry && /"iso_code":/ {
      getline
      gsub(/^[[:space:]]*"/, "", $0)
      sub(/".*/, "", $0)
      print $0
      exit
    }'
}

latest_flow_age_seconds() {
  local newest_epoch now_epoch
  newest_epoch="$(find "$FLOW_DIR" -maxdepth 1 -type f -name 'nfcapd.*' ! -name 'nfcapd.current*' -printf '%T@\n' 2>/dev/null | sort -nr | head -1 | cut -d. -f1 || true)"
  now_epoch="$(date +%s)"
  if [[ -n "${newest_epoch:-}" ]]; then
    echo $(( now_epoch - newest_epoch ))
  else
    echo -1
  fi
}

flow_file_count() {
  find "$FLOW_DIR" -maxdepth 1 -type f -name 'nfcapd.*' 2>/dev/null | wc -l
}

flow_dir_size_bytes() {
  du -sb "$FLOW_DIR" 2>/dev/null | awk '{print $1+0}'
}

{
  echo "# HELP netflow_exporter_last_run_unixtime Last successful run of nfdump_to_prom.sh"
  echo "# TYPE netflow_exporter_last_run_unixtime gauge"
  printf 'netflow_exporter_last_run_unixtime %s\n' "$(date +%s)"

  echo "# HELP netflow_flow_file_count Number of nfcapd flow files currently present"
  echo "# TYPE netflow_flow_file_count gauge"
  printf 'netflow_flow_file_count %s\n' "$(flow_file_count)"

  echo "# HELP netflow_flow_dir_size_bytes Size in bytes of the nfdump flow directory"
  echo "# TYPE netflow_flow_dir_size_bytes gauge"
  printf 'netflow_flow_dir_size_bytes %s\n' "$(flow_dir_size_bytes)"

  echo "# HELP netflow_latest_flow_age_seconds Age in seconds of the newest completed nfcapd flow file"
  echo "# TYPE netflow_latest_flow_age_seconds gauge"
  printf 'netflow_latest_flow_age_seconds %s\n' "$(latest_flow_age_seconds)"

  echo "# HELP netflow_src_flows NetFlow flows per source IP"
  echo "# TYPE netflow_src_flows gauge"
  sudo nfdump -R "$FLOW_DIR" -s srcip/bytes | \
  awk '
  function keyidx_ip() {
    if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 6
    return 0
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_ip()
    if (!k) next
    src = $k
    flows = $(k+1)
    sub(/\(.*/, "", flows)
    if (src ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && flows ~ /^[0-9]+$/)
      printf("netflow_src_flows{srcip=\"%s\"} %s\n", src, flows)
  }' | head -20 || true

  echo "# HELP netflow_dst_flows NetFlow flows per destination IP"
  echo "# TYPE netflow_dst_flows gauge"
  sudo nfdump -R "$FLOW_DIR" -s dstip/bytes | \
  awk '
  function keyidx_ip() {
    if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 6
    return 0
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_ip()
    if (!k) next
    dst = $k
    flows = $(k+1)
    sub(/\(.*/, "", flows)
    if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && flows ~ /^[0-9]+$/)
      printf("netflow_dst_flows{dstip=\"%s\"} %s\n", dst, flows)
  }' | head -20 || true

  echo "# HELP netflow_dst_port_flows NetFlow flows per destination port"
  echo "# TYPE netflow_dst_port_flows gauge"
  sudo nfdump -R "$FLOW_DIR" -s dstport/bytes | \
  awk '
  function keyidx_port() {
    if ($5 ~ /^[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+$/) return 6
    return 0
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_port()
    if (!k) next
    port = $k
    flows = $(k+1)
    sub(/\(.*/, "", flows)
    if (port ~ /^[0-9]+$/ && flows ~ /^[0-9]+$/)
      printf("netflow_dst_port_flows{port=\"%s\"} %s\n", port, flows)
  }' | head -20 || true

  echo "# HELP netflow_src_bytes_mb Approximate megabytes transferred per source IP"
  echo "# TYPE netflow_src_bytes_mb gauge"
  sudo nfdump -R "$FLOW_DIR" -s srcip/bytes | \
  awk '
  function keyidx_ip() {
    if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 6
    return 0
  }
  function to_mb(val, unit, n) {
    n = val
    gsub(/[^0-9.]/, "", n)
    sub(/\(.*/, "", unit)
    if (unit == "G") return n * 1000
    if (unit == "M") return n
    if (unit == "K") return n / 1000
    return n / 1000000
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_ip()
    if (!k) next
    src   = $k
    bytes = $(k+3)
    unit  = $(k+4)
    gsub(/\(.*/, "", unit)
    mb = to_mb(bytes, unit)
    if (src ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && mb ~ /^[0-9.]+$/)
      printf("netflow_src_bytes_mb{srcip=\"%s\"} %.3f\n", src, mb)
  }' | head -20 || true

  echo "# HELP netflow_dst_bytes_mb Approximate megabytes transferred per destination IP"
  echo "# TYPE netflow_dst_bytes_mb gauge"
  sudo nfdump -R "$FLOW_DIR" -s dstip/bytes | \
  awk '
  function keyidx_ip() {
    if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 6
    return 0
  }
  function to_mb(val, unit, n) {
    n = val
    gsub(/[^0-9.]/, "", n)
    sub(/\(.*/, "", unit)
    if (unit == "G") return n * 1000
    if (unit == "M") return n
    if (unit == "K") return n / 1000
    return n / 1000000
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_ip()
    if (!k) next
    dst   = $k
    bytes = $(k+3)
    unit  = $(k+4)
    gsub(/\(.*/, "", unit)
    mb = to_mb(bytes, unit)
    if (dst ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && mb ~ /^[0-9.]+$/)
      printf("netflow_dst_bytes_mb{dstip=\"%s\"} %.3f\n", dst, mb)
  }' | head -20 || true

  echo "# HELP netflow_dst_port_bytes_mb Approximate megabytes transferred per destination port"
  echo "# TYPE netflow_dst_port_bytes_mb gauge"
  sudo nfdump -R "$FLOW_DIR" -s dstport/bytes | \
  awk '
  function keyidx_port() {
    if ($5 ~ /^[0-9]+$/) return 5
    if ($6 ~ /^[0-9]+$/) return 6
    return 0
  }
  function to_mb(val, unit, n) {
    n = val
    gsub(/[^0-9.]/, "", n)
    sub(/\(.*/, "", unit)
    if (unit == "G") return n * 1000
    if (unit == "M") return n
    if (unit == "K") return n / 1000
    return n / 1000000
  }
  $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
    k = keyidx_port()
    if (!k) next
    port  = $k
    bytes = $(k+3)
    unit  = $(k+4)
    gsub(/\(.*/, "", unit)
    mb = to_mb(bytes, unit)
    if (port ~ /^[0-9]+$/ && mb ~ /^[0-9.]+$/)
      printf("netflow_dst_port_bytes_mb{port=\"%s\"} %.3f\n", port, mb)
  }' | head -20 || true

  declare -A ASN_MB
  declare -A ASN_FLOWS
  declare -A COUNTRY_MB

  while read -r ip mb flows; do
    [[ -z "$ip" ]] && continue
    is_private_ip "$ip" && continue

    asn="$(ip_to_asn "$ip")"
    [[ -z "$asn" ]] && asn="UNKNOWN"

    country="$(ip_to_country "$ip")"
    [[ -z "$country" ]] && country="ZZ"

    ASN_MB["$asn"]="$(awk "BEGIN { printf \"%.3f\", ${ASN_MB["$asn"]:-0} + $mb }")"
    ASN_FLOWS["$asn"]=$(( ${ASN_FLOWS["$asn"]:-0} + flows ))
    COUNTRY_MB["$country"]="$(awk "BEGIN { printf \"%.3f\", ${COUNTRY_MB["$country"]:-0} + $mb }")"
  done < <(
    sudo nfdump -R "$FLOW_DIR" -s srcip/bytes | \
    awk '
    function keyidx_ip() {
      if ($5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 5
      if ($6 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 6
      return 0
    }
    function to_mb(val, unit, n) {
      n = val
      gsub(/[^0-9.]/, "", n)
      sub(/\(.*/, "", unit)
      if (unit == "G") return n * 1000
      if (unit == "M") return n
      if (unit == "K") return n / 1000
      return n / 1000000
    }
    $1 ~ /^[0-9][0-9][0-9][0-9]-/ {
      k = keyidx_ip()
      if (!k) next
      ip    = $k
      flows = $(k+1)
      bytes = $(k+3)
      unit  = $(k+4)
      sub(/\(.*/, "", flows)
      gsub(/\(.*/, "", unit)
      mb = to_mb(bytes, unit)
      if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && flows ~ /^[0-9]+$/ && mb ~ /^[0-9.]+$/)
        printf("%s %.3f %s\n", ip, mb, flows)
    }' | head -20
  )

  echo "# HELP netflow_src_asn_bytes_mb Approximate megabytes transferred per ASN (top external sources set)"
  echo "# TYPE netflow_src_asn_bytes_mb gauge"
  for asn in "${!ASN_MB[@]}"; do
    printf 'netflow_src_asn_bytes_mb{asn="%s"} %s\n' "$(escape_label "$asn")" "${ASN_MB[$asn]}"
  done | sort -t' ' -k2,2nr | head -10

  echo "# HELP netflow_src_asn_flows Flows per ASN (top external sources set)"
  echo "# TYPE netflow_src_asn_flows gauge"
  for asn in "${!ASN_FLOWS[@]}"; do
    printf 'netflow_src_asn_flows{asn="%s"} %s\n' "$(escape_label "$asn")" "${ASN_FLOWS[$asn]}"
  done | sort -t' ' -k2,2nr | head -10

  echo "# HELP netflow_src_country_bytes_mb Approximate megabytes transferred per country (top external sources set)"
  echo "# TYPE netflow_src_country_bytes_mb gauge"
  for country in "${!COUNTRY_MB[@]}"; do
    printf 'netflow_src_country_bytes_mb{country="%s"} %s\n' "$(escape_label "$country")" "${COUNTRY_MB[$country]}"
  done | sort -t' ' -k2,2nr | head -10

} > "$TMP"

sudo mv "$TMP" "$OUT"
sudo chmod 644 "$OUT"
