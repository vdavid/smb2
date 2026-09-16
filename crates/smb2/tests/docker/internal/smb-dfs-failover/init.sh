#!/bin/sh
mkdir -p /srv/empty

exec smbd --foreground --no-process-group --debug-stdout
