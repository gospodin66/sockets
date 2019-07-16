<?php

class Timer
{
	private $start_time = null;

	public function __construct()
	{
		$this->start_time = microtime(true);
	}

	public function __destruct()
	{
    	echo 'Timer finished in:: '.$this->get_execution_time().' [s].'.PHP_EOL;
	}

	public function get_execution_time()
	{
	    return microtime(true) - $this->start_time;
	}
}

?>