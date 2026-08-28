FROM alpine:3.21
RUN apk add --no-cache samba
COPY smb.conf /etc/samba/smb.conf
COPY cycle.sh /cycle.sh
RUN chmod +x /cycle.sh \
    && mkdir -p /shares/public && chmod 777 /shares/public
EXPOSE 445
# No healthcheck — the whole point is the server goes up and down.
CMD ["/cycle.sh"]
