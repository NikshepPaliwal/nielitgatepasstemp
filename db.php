<?php
echo "Testing DB...<br>";

$host = "svc-3482219c-a389-4079-b18b-d50662524e8a-shared-dml.aws-virginia-6.svc.singlestore.com";
$user = "nikshep-e7718";
$pass = '4nCGWADrJ$^rexoL_t0%kqp5';
$db   = "gatepass_db";

$conn = @mysqli_connect($host, $user, $pass, $db);

if (!$conn) {
    die("DB FAILED: " . mysqli_connect_error());
}

echo "DB OK!";
