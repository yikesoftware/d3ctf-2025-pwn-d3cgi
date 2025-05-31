#!/bin/sh

echo ${FLAG} > /flag
chmod 444 /flag
ln -s /flag /home/ctf/flag
runuser -u ctf -- /home/ctf/run.sh
sleep infinity