#!/bin/sh
# The namespace root's own directory is never served: smbd refuses the tree
# connect and answers a referral instead. It still has to exist for smbd to
# start.
mkdir -p /srv/empty /srv/plain
echo "An ordinary share on the namespace server." > /srv/plain/plain.txt

exec smbd --foreground --no-process-group --debug-stdout
