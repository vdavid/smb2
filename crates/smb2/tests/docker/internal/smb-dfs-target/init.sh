#!/bin/sh
# Create the target share directory with test data.
mkdir -p /srv/files/subdir
chmod 777 /srv/files

echo "Hello from DFS target!" > /srv/files/hello.txt
echo "Nested file" > /srv/files/subdir/nested.txt

exec smbd --foreground --no-process-group --debug-stdout
