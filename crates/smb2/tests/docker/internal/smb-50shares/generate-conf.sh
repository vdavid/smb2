#!/bin/sh
# Generate smb.conf with 50 shares.
cat > /etc/samba/smb.conf <<'HEADER'
[global]
server min protocol = SMB2_02
server max protocol = SMB3_11
map to guest = Bad User
log level = 1
HEADER

for i in $(seq 1 50); do
    dir="/shares/share_$(printf '%02d' "$i")"
    mkdir -p "$dir"
    chmod 777 "$dir"
    cat >> /etc/samba/smb.conf <<SHARE

[share_$(printf '%02d' "$i")]
path = $dir
read only = no
guest ok = yes
browseable = yes
SHARE
done
