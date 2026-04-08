FROM alpine:3.21
RUN apk add --no-cache samba iproute2
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /shares/public && chmod 777 /shares/public
EXPOSE 445
HEALTHCHECK --interval=2s --timeout=5s --retries=15 \
    CMD nc -z localhost 445
CMD ["/entrypoint.sh"]
