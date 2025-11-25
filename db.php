<?php

class Database
{
    private $host = "localhost";
    private $user = "root";
    private $pass = "";            // Default XAMPP password
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

    // Reusable query function
    public function run($sql, $params = [])
    {
        $stmt = $this->conn->prepare($sql);

        if ($params) {
            // Create string like "ssi"
            $types = str_repeat("s", count($params));
            $stmt->bind_param($types, ...$params);
        }

        $stmt->execute();

        return $stmt->get_result();
    }
}
