FROM alpine:3.21
RUN apk add --no-cache samba
COPY smb.conf /etc/samba/smb.conf
RUN mkdir -p /shares/homes/admin /shares/timemachine/backups \
    && echo "Synology home file" > /shares/homes/admin/notes.txt \
    && echo "TimeMachine backup marker" > /shares/timemachine/backups/backup_2024.txt \
    && echo "NAS configuration" > /shares/homes/admin/config.txt \
    && chmod -R 777 /shares/homes /shares/timemachine
EXPOSE 445
HEALTHCHECK --interval=2s --timeout=3s --retries=10 \
    CMD nc -z localhost 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
