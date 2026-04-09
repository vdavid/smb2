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

# Create test user (with pre-auth required)
kadmin.local -q "addprinc -pw testpass +requires_preauth testuser@TEST.LOCAL" 2>/dev/null || true

# Create service principal for Samba
# Use both cifs/localhost and host/localhost
kadmin.local -q "addprinc -randkey cifs/localhost@TEST.LOCAL" 2>/dev/null || true
kadmin.local -q "addprinc -randkey host/localhost@TEST.LOCAL" 2>/dev/null || true

# Export keytab for Samba (both service principals)
kadmin.local -q "ktadd -k /etc/samba/samba.keytab cifs/localhost@TEST.LOCAL" 2>/dev/null || true
kadmin.local -q "ktadd -k /etc/samba/samba.keytab host/localhost@TEST.LOCAL" 2>/dev/null || true

chmod 600 /etc/samba/samba.keytab

echo "KDC setup complete"
SCRIPT
RUN chmod +x /setup-kdc.sh

# Configure Samba with Kerberos
RUN cat > /etc/samba/smb.conf << 'EOF'
[global]
    workgroup = TESTLOCAL
    realm = TEST.LOCAL
    netbios name = LOCALHOST
    security = user
    server role = standalone server

    # Kerberos auth via keytab
    kerberos method = dedicated keytab
    dedicated keytab file = /etc/samba/samba.keytab

    # Signing
    server signing = mandatory

    # Map Kerberos principal to local user
    username map = /etc/samba/smbusers

    # Logging
    log level = 3 auth:10
    log file = /var/log/samba/log.%m

[public]
    path = /srv/share
    read only = no
    guest ok = no
    create mask = 0666
    directory mask = 0777
    valid users = testuser
EOF

# Create username mapping (Kerberos principal -> local user)
RUN echo "testuser = testuser@TEST.LOCAL" > /etc/samba/smbusers

# Create share directory
RUN mkdir -p /srv/share /var/log/samba && chmod 777 /srv/share

# Create local user and Samba user
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
echo "KDC started on port 88"

# Start Samba
smbd --foreground --no-process-group &
echo "Samba started on port 445"

# Wait for services
sleep 1
echo "Ready"

# Keep running
wait
SCRIPT
RUN chmod +x /entrypoint.sh

EXPOSE 88/udp 88/tcp 445/tcp

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s \
    CMD smbclient -L localhost -U testuser%testpass 2>/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
