FROM alpine:3.21

RUN apk add --no-cache samba-dc samba-common-tools krb5 bash

# Entrypoint provisions on first run and starts Samba AD DC
RUN cat > /entrypoint.sh << 'SCRIPT'
#!/bin/bash
set -e

if [ ! -f /var/lib/samba/private/secrets.ldb ]; then
    echo "Provisioning AD DC..."
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --realm=TEST.LOCAL \
        --domain=TESTLOCAL \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass='AdminPass1!' \
        --use-rfc2307

    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    # Start Samba temporarily to create user
    samba &
    sleep 3
    samba-tool user create testuser testpass 2>/dev/null || true

    # Add a share
    mkdir -p /srv/share && chmod 777 /srv/share
    cat >> /etc/samba/smb.conf << 'SMBEOF'

[public]
    path = /srv/share
    read only = no
SMBEOF

    # Stop temporary Samba
    kill %1 2>/dev/null; wait 2>/dev/null
    echo "Provisioning complete"
fi

exec samba --foreground --no-process-group
SCRIPT
RUN chmod +x /entrypoint.sh

EXPOSE 88/udp 88/tcp 445/tcp

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s \
    CMD smbclient -L localhost -U 'Administrator%AdminPass1!' 2>/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
