#!/bin/sh
# Create the DFS root directory and a DFS link.
# Samba DFS links are symlinks with the "msdfs:" prefix.
mkdir -p /srv/dfs

# "data" -> smb-dfs-target's "files" share
ln -s "msdfs:smb-dfs-target\\files" /srv/dfs/data

exec smbd --foreground --no-process-group --debug-stdout
