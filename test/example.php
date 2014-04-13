<?php

include __DIR__.'/bootstrap.php';

use Wow\Util\WowJwt as JWT;

$payload = '{"iss":"ant"}';
$key     = '1234567890';
$algo    = 'HS256';

$verify  = true;
$encrypt = false;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";

$verify  = true;
$encrypt = true;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";

$verify  = false;
$encrypt = false;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";

$verify  = false;
$encrypt = true;

$t = JWT::encode($payload, $key, $algo, $encrypt);
echo $t."\n";
$t = JWT::decode($t, $key, $verify, $encrypt);
echo $t."\n";
