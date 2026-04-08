FROM alpine:3.21
RUN apk add --no-cache samba
COPY smb.conf /etc/samba/smb.conf
RUN mkdir -p /shares/private && chmod 777 /shares/private \
    && adduser -D testuser \
    && printf "testpass\ntestpass\n" | smbpasswd -a -s testuser
EXPOSE 445
HEALTHCHECK --interval=2s --timeout=3s --retries=10 \
    CMD nc -z localhost 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
