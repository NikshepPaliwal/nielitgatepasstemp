<?php
$module = $_GET['module'] ?? 'User';
$action = $_GET['action'] ?? 'loginForm';

require_once $module . ".class.php";

$obj = new $module();

if (method_exists($obj, $action)) {
    $obj->$action(); // call the function inside the class
} else {
    include "views/error.php";
}
