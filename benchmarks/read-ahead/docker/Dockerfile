FROM alpine:3.24
RUN apk add --no-cache samba iproute2
COPY smb.conf /etc/samba/smb.conf
COPY --chmod=755 stall.sh /stall.sh
RUN mkdir -p /shares/public && chmod 777 /shares/public
EXPOSE 445
HEALTHCHECK --interval=2s --timeout=3s --retries=10 \
    CMD nc -z localhost 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
