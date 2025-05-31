#!/bin/sh

export LD_LIBRARY_PATH=/home/ctf/libs 
/home/ctf/lighttpd -f /home/ctf/lighttpd.conf
if [ $? -ne 0 ]; then
    echo "Failed to start lighttpd!"
    exit 1
fi
echo "HTTP server is running..."