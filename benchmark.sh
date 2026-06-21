#!/bin/bash
IP_MAP=$1
STATS_MAP=$2
REQUESTS=20

measure() {
    local label=$1
    BEFORE=$(sudo bpftool map dump id $STATS_MAP | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['value'])")
    
    for i in $(seq 1 $REQUESTS); do
        curl -s --max-time 2 http://10.0.0.2:8080 > /dev/null
    done
    
    AFTER=$(sudo bpftool map dump id $STATS_MAP | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['value'])")
    PACKETS=$((AFTER - BEFORE))
    echo "$label: $REQUESTS requests → $PACKETS packets processed"
}

echo "=== Rule Scaling Benchmark ==="

echo "--- 0 rules ---"
measure "0 rules"

./insert_rules.sh $IP_MAP 10 > /dev/null
echo "--- 10 rules ---"
measure "10 rules"

./insert_rules.sh $IP_MAP 100 > /dev/null
echo "--- 100 rules ---"
measure "100 rules"

./insert_rules.sh $IP_MAP 1000 > /dev/null
echo "--- 1000 rules ---"
measure "1000 rules"

echo "=== Done ==="
