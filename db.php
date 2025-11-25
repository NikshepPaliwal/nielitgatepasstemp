<?php

class Database
{
    private $host = "svc-3482219c-a389-4079-b18b-d50662524e8a-shared-dml.aws-virginia-6.svc.singlestore.com";
    private $user = "nikshep-e7718";
    private $pass = '4nCGWADrJ$^rexoL_t0%kqp5';     // FIXED: single quotes
    private $db   = "gatepass_db";

    public $conn;

    public function __construct()
    {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

        try {
            $this->conn = new mysqli(
                $this->host,
                $this->user,
                $this->pass,
                $this->db
            );

            $this->conn->set_charset("utf8mb4");

        } catch (Exception $e) {
            die("❌ Database Connection Failed: " . $e->getMessage());
        }
    }

    public function run($sql, $params = [])
    {
        $stmt = $this->conn->prepare($sql);

        if ($params) {
            $types = str_repeat("s", count($params));
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();

        return $stmt->get_result();
    }
}


