FROM alpine:3.21

# Install Kerberos KDC + Samba
RUN apk add --no-cache \
    krb5 \
    krb5-server \
    samba \
    samba-common-tools \
    bash

# Kerberos realm config
ENV KRB5_REALM=TEST.LOCAL
ENV KRB5_KDC=localhost
ENV KRB5_ADMIN_SERVER=localhost

# Create krb5.conf
RUN cat > /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    TEST.LOCAL = {
        kdc = localhost
        admin_server = localhost
    }

[domain_realm]
    .test.local = TEST.LOCAL
    test.local = TEST.LOCAL
EOF

# Create KDC database and principals
RUN cat > /setup-kdc.sh << 'SCRIPT'
#!/bin/bash
set -e

# Create KDC database
kdb5_util create -s -P masterpassword 2>/dev/null || true

# Create admin principal
kadmin.local -q "addprinc -pw adminpass admin/admin@TEST.LOCAL" 2>/dev/null || true

# Create test user
kadmin.local -q "addprinc -pw testpass testuser@TEST.LOCAL" 2>/dev/null || true

# Create service principal for Samba (cifs/localhost)
kadmin.local -q "addprinc -randkey cifs/localhost@TEST.LOCAL" 2>/dev/null || true

# Export keytab for Samba
kadmin.local -q "ktadd -k /etc/samba/samba.keytab cifs/localhost@TEST.LOCAL" 2>/dev/null || true

echo "KDC setup complete"
SCRIPT
RUN chmod +x /setup-kdc.sh

# Configure Samba for Kerberos
RUN cat > /etc/samba/smb.conf << 'EOF'
[global]
    workgroup = TESTLOCAL
    realm = TEST.LOCAL
    security = ads
    kerberos method = dedicated keytab
    dedicated keytab file = /etc/samba/samba.keytab
    server signing = mandatory

    # Use standalone mode (no actual AD join needed)
    security = user
    server role = standalone server

    # Accept Kerberos auth via SPNEGO
    auth methods = guest sam

    # Logging
    log level = 2
    log file = /var/log/samba/log.%m

[public]
    path = /srv/share
    read only = no
    guest ok = no
    create mask = 0666
    directory mask = 0777
EOF

# Create share directory
RUN mkdir -p /srv/share /var/log/samba && \
    chmod 777 /srv/share

# Create Samba user matching the Kerberos principal
RUN adduser -D -H testuser && \
    echo -e "testpass\ntestpass" | smbpasswd -a -s testuser

# Entrypoint: start KDC + Samba
RUN cat > /entrypoint.sh << 'SCRIPT'
#!/bin/bash
set -e

# Initialize KDC
/setup-kdc.sh

# Start KDC
krb5kdc
echo "KDC started"

# Start Samba
smbd --foreground --no-process-group &
echo "Samba started"

# Wait for services
sleep 1
echo "Ready"

# Keep running
wait
SCRIPT
RUN chmod +x /entrypoint.sh

EXPOSE 88/udp 88/tcp 445/tcp

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s \
    CMD smbclient -L localhost -U testuser%testpass -N 2>/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
