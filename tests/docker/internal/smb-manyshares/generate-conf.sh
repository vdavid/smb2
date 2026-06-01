#!/bin/sh
# Generate smb.conf with many shares, each carrying a long comment.
#
# Why: the srvsvc NetShareEnum reply for these shares is well over 64 KiB, so it
# can't come back in a single 64 KiB pipe read. The server returns it either as
# many DCE/RPC fragments (PFC_LAST_FRAG only on the last) or as chunked
# STATUS_BUFFER_OVERFLOW reads -- both exercise the client's reassembly path,
# which smb-50shares (a single-fragment reply) cannot. See
# `manyshares_list_all_spans_multiple_fragments` in docker_integration.rs.
SHARE_COUNT=200

# ~190-char comment. Per-share NDR cost is roughly 12 (fixed) + ~32 (name) +
# ~404 (comment) ≈ 450 bytes, so 200 shares ≈ 90 KiB of stub -- comfortably past
# one 64 KiB read.
COMMENT="This is a deliberately long share comment used to inflate the srvsvc NetShareEnum response past one 64 KiB pipe read, so the listing spans multiple RPC fragments and exercises the client reassembly path during share-enumeration testing."

cat > /etc/samba/smb.conf <<'HEADER'
[global]
server min protocol = SMB2_02
server max protocol = SMB3_11
map to guest = Bad User
log level = 1
HEADER

i=1
while [ "$i" -le "$SHARE_COUNT" ]; do
    name="share_$(printf '%03d' "$i")"
    dir="/shares/$name"
    mkdir -p "$dir"
    chmod 777 "$dir"
    cat >> /etc/samba/smb.conf <<SHARE

[$name]
path = $dir
comment = $COMMENT
read only = no
guest ok = yes
browseable = yes
SHARE
    i=$((i + 1))
done
