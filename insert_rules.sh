#!/bin/bash
MAP_ID=$1
COUNT=$2
echo "Inserting $COUNT rules into map $MAP_ID..."
for i in $(seq 1 $COUNT); do
    OCTET3=$(( (i - 1) / 254 ))
    OCTET4=$(( (i - 1) % 254 + 1 ))
    O3=$(printf "0x%02x" $OCTET3)
    O4=$(printf "0x%02x" $OCTET4)
    # using 192.168.x.x — won't collide with test traffic on 10.0.0.x
    sudo bpftool map update id $MAP_ID \
        key 0x20 0x00 0x00 0x00 0xc0 0xa8 $O3 $O4 \
        value 0x01 0x00 0x00 0x00 2>/dev/null
done
echo "Done. Current rule count:"
sudo bpftool map dump id $MAP_ID | grep -c "key"
