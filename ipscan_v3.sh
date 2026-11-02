#!/bin/bash

# ==============================================================================
# Advanced Subnet & IP Range Scanner (Multiple Target Support)
# Format Target (dapat dipisah dengan koma untuk multiple target):
#   - CIDR      : ./ipscan_v2.sh 192.168.1.0/24
#   - Range IP  : ./ipscan_v2.sh 192.168.1.10-192.168.1.50
#   - Single IP : ./ipscan_v2.sh 192.168.1.1
#   - Multiple  : ./ipscan_v2.sh 192.168.1.1,192.168.1.10-192.168.1.20,10.0.0.0/28
# ==============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Konversi IP Address ke Format Angka Integer
ip2int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

# Konversi Angka Integer ke IP Address
int2ip() {
    local int=$1
    echo "$(( (int >> 24) & 255 )).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$(( int & 255 ))"
}

# Parser Target Input Tunggal (CIDR, Range, atau Single IP)
parse_single_target() {
    local target="$1"
    
    if [[ "$target" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$ ]]; then
        # Format CIDR (contoh: 192.168.1.0/24)
        local ip="${BASH_REMATCH[1]}"
        local mask_bits="${BASH_REMATCH[2]}"
        
        local ip_num=$(ip2int "$ip")
        local mask=$(( (0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF ))
        local net_num=$(( ip_num & mask ))
        local broadcast_num=$(( net_num | (~mask & 0xFFFFFFFF) ))
        
        if [ "$mask_bits" -eq 32 ]; then
            echo "$ip_num $ip_num"
        elif [ "$mask_bits" -eq 31 ]; then
            echo "$net_num $broadcast_num"
        else
            echo "$(( net_num + 1 )) $(( broadcast_num - 1 ))"
        fi
    elif [[ "$target" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        # Format Range IP (contoh: 192.168.1.10-192.168.1.50)
        local start_int=$(ip2int "${BASH_REMATCH[1]}")
        local end_int=$(ip2int "${BASH_REMATCH[2]}")
        echo "$start_int $end_int"
    elif [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Format Single IP
        local ip_num=$(ip2int "$target")
        echo "$ip_num $ip_num"
    else
        echo "ERROR"
    fi
}

TARGET="${1:-192.168.1.0/24}"
TIMEOUT="${2:-1}"
MODE="${3:-all}" # 'all' (UP & DOWN) atau 'up_only' (hanya UP)

TEMP_LOG=$(mktemp)
ALL_IPS_FILE=$(mktemp)
trap 'rm -f "$TEMP_LOG" "$ALL_IPS_FILE"' EXIT

# Memproses target yang dipisahkan koma
IFS=',' read -ra TARGET_ARRAY <<< "$TARGET"

for t in "${TARGET_ARRAY[@]}"; do
    t=$(echo "$t" | xargs)
    [ -z "$t" ] && continue
    
    res=$(parse_single_target "$t")
    if [ "$res" == "ERROR" ]; then
        echo -e "${RED}Format target '$t' tidak valid!${NC}"
        echo -e "Penggunaan: $0 <target1,target2,...> [timeout_detik] [show_down: all|up_only]"
        echo -e "Contoh    : $0 192.168.1.1,192.168.1.10-192.168.1.50,10.0.0.0/28"
        exit 1
    fi
    
    read -r START_INT END_INT <<< "$res"
    for (( i=START_INT; i<=END_INT; i++ )); do
        echo "$i" >> "$ALL_IPS_FILE"
    done
done

# Menghapus IP duplikat jika ada rentang yang beririsan
sort -u -n "$ALL_IPS_FILE" -o "$ALL_IPS_FILE"
TOTAL_HOSTS=$(wc -l < "$ALL_IPS_FILE")

echo -e " "
echo -e " "
echo -e "                  ..(%%%/***,........,,,,*****,....                      "
echo -e "                .....    ..,,**/*,,,.................                   "
echo -e "             .*,../(*.,.........,.,...,,(,........,,..                   "
echo -e "          .,/*(#/*..,.,...,.,,,.,,,.,,,*,.*/,.,,...,,,....               "
echo -e "         .*/((/*,,/**,*,,*.,,,/*,,.,,/*(///,..*,,**,,,*,....             "
echo -e "       .,*,...,*,***(*,,*,*/(*,/,,*..,,,**((,,*.***,***/,....            "
echo -e "      .,*.  ...,(//,,*,,,.,//(%(#((,..,,,*((#((*.****,*/(*.....          "
echo -e "    ,**,*. .,../((#*,.......*#&&%/,,/.,...**###/,****/*/(*......         "
echo -e "   ,**,**..*(/(((#/,, .    ..*&&%(.  .  .. ,/#%%(******/(*........       "
echo -e "   ,**,***.*//#%(/*.,..,.., ..(&%#...*%.....,/##(****(/*/*.........      "
echo -e "   */****/((#/(#(*,./.**.**. ,,&%(. ./.*,.,..*#(*/*(/,,,//.........      "
echo -e "   */***,*/##(/(#*,..,, ..  ..,%%(, ...,.. .,/((((*....*/...........     "
echo -e "   //****,*/%#(###*,,.. ....,,(//***. ...,,//(##(*,....*/..,.........    "
echo -e "   /(**/***/*#%###((//#//(#&%((/((*/*(##/,*/###(*.....,/(.,,,,,.....     "
echo -e "   ,##(/****///#&%%(((/#%&&&&#,//.*.,*##(/####(((,....,*(**,,......      "
echo -e "   ./(((((/(///((#&&%(*,,,(%%#,//...,((%%%%(/((//*...,,*(*,,.......      "
echo -e "   ../(///((((#######%%%&&&%&&&%/*#&&&&%%#(((///(/,,,,,,/(,,,......      "
echo -e "   ..,/((**,....,/(%##%%%%%%%%%&&&&%%####((//**/##/*,.,,,*/(,.....       "
echo -e "    ..,((****,.,*/(#%%%########((/////////*.,,,,((((///////(/....        "
echo -e "      .*#(/*,,,,//////(%&%%%##########/*,,.. ..,((((###(#((((...         "
echo -e "       .*(/,..,//,,,,*****/#%%%%%%##((/*,,..,,,./##(((*(#/*(/..          "
echo -e "          .,,,,*/**(####(//*/////((#####(/**//(/*,,,**,//*(*,.           "
echo -e " "
echo -e "                        Prepared by aw0x0410 "
echo -e "                    https://github.com/anggrdwjy"
echo -e "${BOLD}--------------------------------------------------------------------${NC}"
echo -e "${BOLD} Target Pemindaian : ${YELLOW}${TARGET}${NC}"
echo -e "${BOLD} Total IP Unik     : ${TOTAL_HOSTS} IP${NC}"
echo -e "${BOLD}--------------------------------------------------------------------${NC}"

scan_host() {
    local ip="$1"
    local timeout="$2"
    local temp_file="$3"
    local status="DOWN"
    local hostname="-"
    local mac="-"
    
    if ping -c 1 -W "$timeout" "$ip" &>/dev/null; then
        status="UP"
        
        # Ambil Hostname via DNS
        hostname=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF}' | sed 's/\.$//')
        [ -z "$hostname" ] && hostname="-"
        
        # Ambil MAC Address via 'ip neighbor' atau 'arp'
        mac=$(ip neighbor show "$ip" 2>/dev/null | awk '{print $5}' | grep -E '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
        [ -z "$mac" ] && mac=$(arp -n "$ip" 2>/dev/null | awk '/:/{print $3}')
        [ -z "$mac" ] && mac="-"
    fi
    
    echo "$ip|$status|$hostname|$mac" >> "$temp_file"
}

export -f scan_host

# Batasi jumlah background job bersamaan agar tidak overload sistem
MAX_JOBS=50
job_count=0

while read -r i; do
    ip=$(int2ip "$i")
    scan_host "$ip" "$TIMEOUT" "$TEMP_LOG" &
    
    ((job_count++))
    if [ "$job_count" -ge "$MAX_JOBS" ]; then
        wait -n 2>/dev/null || wait
        ((job_count--))
    fi
done < "$ALL_IPS_FILE"

wait

# Tampilkan Tabel Hasil
printf "${BOLD}%-16s %-8s %-30s %-18s${NC}\n" "IP Address" "Status" "Hostname" "MAC Address"
echo "--------------------------------------------------------------------"
sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n "$TEMP_LOG" | while IFS='|' read -r ip status host mac; do
    if [ "$status" == "UP" ]; then
        printf "${GREEN}%-16s %-8s${NC} %-30s %-18s\n" "$ip" "$status" "$host" "$mac"
    elif [ "$MODE" == "all" ]; then
        printf "${RED}%-16s %-8s${NC} %-30s %-18s\n" "$ip" "$status" "$host" "$mac"
    fi
done

total_up=$(grep -c "|UP|" "$TEMP_LOG" || true)
total_down=$(grep -c "|DOWN|" "$TEMP_LOG" || true)

echo "--------------------------------------------------------------------"
echo -e "${BOLD}Ringkasan:${NC} Total: $TOTAL_HOSTS | ${GREEN}Aktif (UP): $total_up${NC} | ${RED}Mati (DOWN): $total_down${NC}"
echo -e " "
