<?php

//$num_pattern = '/^[0-9]+$/';	
function calllogin(){

	$pass_c = "../passc/pass";

	$pid = pcntl_fork();

		switch($pid) {
  	case -1:
     	echo "Fork error.\n";
     	return false;
  	case 0:
     	pcntl_exec($pass_c);
     	exit();
  	default:
     	break;
    }

    while (pcntl_waitpid(0, $status) != -1) {
	  	$status = pcntl_wexitstatus($status);

	  	if($status === 1)
        pcntl_exec($pass_c);
	  	
      else
        echo "Login Success!\n";
    }

    return true;
}

?>