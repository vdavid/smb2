#!/bin/sh
# Create the DFS root directory and a DFS link.
# Samba DFS links are symlinks with the "msdfs:" prefix.
mkdir -p /srv/dfs

# "data" -> smb-dfs-target's "files" share
ln -s "msdfs:smb-dfs-target\\files" /srv/dfs/data

# A plain file in the root share itself (guest can't write here), so a test
# can see what the server names a file opened through a `server\share\` path.
printf 'root\n' > /srv/dfs/Root-File.txt

exec smbd --foreground --no-process-group --debug-stdout
