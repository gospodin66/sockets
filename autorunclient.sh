#!/bin/bash
# */1 * * * * /bin/bash ~/sockets/autorunclient.sh
if ps -C php h | grep -q client.php
then
	printf "Service is running.\n"
else
	php ~/sockets/client.php -h <ip> -p <port>
fi
