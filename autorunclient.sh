#!/bin/bash

if ps -C php h | grep -q client.php
then
	printf "Service is running.\n"
else
	php ~/sockets/client.php -h 192.168.1.7 -p 1111
fi