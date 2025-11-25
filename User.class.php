<?php 
//url ex: ...55/nielitndu/gatepass/semesterCourses

class User 
{
	
	



	
	protected function semesterCourses()
	{
		global $conn;

		connecttodb("r", "gatepass_db");
		$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


	}
function wardenLogin()
{
    // Force JSON API
    header("Content-Type: application/json; charset=utf-8");
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type");

    // Handle OPTIONS preflight
    if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
        echo json_encode(["success" => true]);
        exit;
    }

    // Load DB
    require_once "db.php";
    $db = new Database();
    $conn = $db->conn;

    $response = [];

    try {

        $method = $_SERVER["REQUEST_METHOD"];

        // Accept both POST and GET for testing
        if ($method === "POST") {
            $raw = file_get_contents("php://input");
            $data = json_decode($raw, true);

            if (!is_array($data)) {
                throw new Exception("Invalid JSON body", 400);
            }

        } elseif ($method === "GET") {
            // GET mode only for testing
            $data = [
                "email"     => $_GET["email"] ?? "",
                "password"  => $_GET["password"] ?? "",
                "fcm_token" => $_GET["fcm_token"] ?? ""
            ];
        } else {
            throw new Exception("Invalid Method", 405);
        }

        // Extract fields
        $email = trim($data["email"] ?? "");
        $password = trim($data["password"] ?? "");
        $fcm_token = trim($data["fcm_token"] ?? "");

        // Validate
        if ($email === "" || $password === "") {
            throw new Exception("Email and password are required", 400);
        }

        // Check warden
        $stmt = $conn->prepare("SELECT id, email, password, gender FROM wardens WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            throw new Exception("Invalid login credentials", 401);
        }

        $warden = $result->fetch_assoc();

        if ($warden["password"] !== $password) {
            throw new Exception("Invalid login credentials", 401);
        }

        // Login success → No sessions, API-only output
        $response = [
            "success" => true,
            "message" => "Login successful",
            "warden" => [
                "id"     => $warden["id"],
                "email"  => $warden["email"],
                "gender" => $warden["gender"],
                "name"   => strstr($warden["email"], "@", true)
            ]
        ];

        // Update FCM if provided
        if ($fcm_token !== "") {
            $u = $conn->prepare("UPDATE wardens SET fcm_token = ? WHERE id = ?");
            $u->bind_param("si", $fcm_token, $warden["id"]);
            $u->execute();
        }

        http_response_code(200);

    } catch (Exception $e) {

        http_response_code($e->getCode() ?: 500);

        $response = [
            "success" => false,
            "message" => $e->getMessage()
        ];
    }

    echo json_encode($response);
    exit;
}


// warden dashboard...
function wardenDashboard() {

    session_start();

    // User must be logged in
    if (!isset($_SESSION["warden_id"])) {
        header("Location: https://nielitgatepasstemp.onrender.com/index.php?module=User&action=wardenLogin");
        exit;
    }

    require_once "db.php";
    $db = new Database();
    $conn = $db->conn;

    $warden_id = $_SESSION["warden_id"];
    $warden_name = $_SESSION["warden_name"];
    $gender = $_SESSION["warden_gender"];

    // Helper: Count gatepass requests
    function getRequestCount($conn, $status, $gender) {
        $stmt = $conn->prepare("
            SELECT COUNT(*) AS c 
            FROM gatepass_requests g 
            JOIN students s ON g.student_id = s.id
            WHERE g.status = ? AND s.gender = ?
        ");
        $stmt->bind_param("ss", $status, $gender);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc()["c"];
    }

    $pendingCount  = getRequestCount($conn, "Pending", $gender);
    $approvedCount = getRequestCount($conn, "Approved", $gender);
    $rejectedCount = getRequestCount($conn, "Rejected", $gender);

	?>
	<!DOCTYPE html>
	<html>
	<head>
		<title>Warden Dashboard</title>
		<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
		<style>
			body { font-family:Poppins; background:#f4f4f4; }
			.navbar { background:#667eea; padding:15px; color:white; }
			.dashboard { padding:30px; display:flex; gap:20px; }
			.card { background:white; padding:20px; border-radius:10px; width:250px; box-shadow:0 4px 6px rgba(0,0,0,0.1); }
			.card h2 { margin-bottom:10px; }
		</style>
	</head>
	<body>

	<div class="navbar">
		<h1>Welcome, <?= htmlspecialchars($warden_name); ?> (<?= htmlspecialchars($gender) ?>)</h1>
	</div>

	<div class="dashboard">

		<div class="card">
			<h2>Pending: <?= $pendingCount ?></h2>
		</div>

		<div class="card">
			<h2>Approved: <?= $approvedCount ?></h2>
		</div>

		<div class="card">
			<h2>Rejected: <?= $rejectedCount ?></h2>
		</div>

	</div>

	</body>
	</html>

	<?php
}


	// student login...

	function studentLogin() {

			session_start();

			require_once "db.php";
			$db = new Database();
			$conn = $db->conn;

			// Detect API request (POST + JSON)
			$isApi = (
				$_SERVER["REQUEST_METHOD"] === "POST" &&
				isset($_SERVER["CONTENT_TYPE"]) &&
				strpos($_SERVER["CONTENT_TYPE"], "application/json") !== false
			);

			// =======================================================
			// 1️⃣ API LOGIN (Mobile App / Flutter)
			// =======================================================
			if ($isApi) {

				header("Content-Type: application/json; charset=utf-8");
				header("Access-Control-Allow-Origin: *");

				$data = json_decode(file_get_contents("php://input"), true);

				if (!isset($data["email"], $data["password"])) {
					echo json_encode(["success" => false, "message" => "Email & Password required"]);
					exit;
				}

				$email = $data["email"];
				$password = $data["password"];
				$fcm_token = $data["fcm_token"] ?? "";

				$stmt = $conn->prepare("SELECT * FROM students WHERE email = ? LIMIT 1");
				$stmt->bind_param("s", $email);
				$stmt->execute();
				$res = $stmt->get_result();

				if ($res->num_rows === 0) {
					echo json_encode(["success" => false, "message" => "Invalid credentials"]);
					exit;
				}

				$student = $res->fetch_assoc();

				// Password verification
				if (!password_verify($password, $student['password'])) {
					echo json_encode(["success" => false, "message" => "Invalid password"]);
					exit;
				}

				// Create session
				$_SESSION["student_id"] = $student["id"];
				$_SESSION["student_name"] = $student["name"];

				// Save FCM Token
				if (!empty($fcm_token)) {
					$s2 = $conn->prepare("UPDATE students SET fcm_token=? WHERE id=?");
					$s2->bind_param("si", $fcm_token, $student["id"]);
					$s2->execute();
					$s2->close();
				}

				echo json_encode([
					"success" => true,
					"message" => "Login successful",
					"redirect" => "index.php?module=User&action=studentDashboard"
				]);
				exit;
			}

			// =======================================================
			// 2️⃣ WEB LOGIN (HTML UI)
			// =======================================================
			?>

				<!DOCTYPE html>
				<html>
				<head>
					<title>Student Login</title>
					<link rel="stylesheet" href="assets/style.css">
				</head>
				<body>

				<div class="form-container">
					<h2>Student Login</h2>

					<input type="email" id="email" placeholder="Email">
					<input type="password" id="password" placeholder="Password">

					<button onclick="login()">Login</button>

					<p><a href="index.php">Back</a></p>
				</div>

				<script>

				async function login() {

			const email = document.getElementById("email").value.trim();
			const password = document.getElementById("password").value.trim();

			const response = await fetch("index.php?module=User&action=studentLoginAPI", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email, password })
			});

			const result = await response.json();

			alert(result.message);

			if (result.success) {
				window.location.href = result.redirect;
			}
		}


				</script>

				</body>
				</html>

				<?php
}



	// student dashboard.....

	function studentDashboard() {

			session_start();

			if (!isset($_SESSION["student_id"])) {
				header("Location: index.php?module=User&action=studentLogin");
				exit;
			}

			require_once "db.php";
			$db = new Database();
			$conn = $db->conn;

			$student_id = $_SESSION["student_id"];
			$student = null;

			// Fetch student details
			$stmt = $conn->prepare("SELECT name, email, mobile, class, semester FROM students WHERE id = ?");
			$stmt->bind_param("i", $student_id);
			$stmt->execute();
			$student = $stmt->get_result()->fetch_assoc();
			$stmt->close();

			// Fetch gatepasses
			$stmt = $conn->prepare("
				SELECT *, CONCAT(from_date,' - ',to_date) AS dateRange
				FROM gatepass_requests 
				WHERE student_id=?
				ORDER BY created_at DESC
			");
			$stmt->bind_param("i", $student_id);
			$stmt->execute();
			$res = $stmt->get_result();

			$approved = [];
			$pending  = [];
			$rejected = [];

			while ($p = $res->fetch_assoc()) {
				if ($p["status"] == "Approved") $approved[] = $p;
				if ($p["status"] == "Pending")  $pending[]  = $p;
				if ($p["status"] == "Rejected") $rejected[] = $p;
			}

			?>

		<!DOCTYPE html>
		<html>
		<head>
			<title>Student Dashboard</title>
			<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
		</head>
		<body>

		<h1>Welcome <?= htmlspecialchars($student["name"]) ?></h1>

		<h2>Gate Passes</h2>

		<h3>Approved</h3>
		<?= empty($approved) ? "No approved passes" : "" ?>
		<?php foreach ($approved as $gp): ?>
			<div><?= $gp["reason"] ?> - <?= $gp["status"] ?></div>
		<?php endforeach; ?>

		<h3>Pending</h3>
		<?= empty($pending) ? "No pending passes" : "" ?>
		<?php foreach ($pending as $gp): ?>
			<div><?= $gp["reason"] ?> - <?= $gp["status"] ?></div>
		<?php endforeach; ?>

		<h3>Rejected</h3>
		<?= empty($rejected) ? "No rejected passes" : "" ?>
		<?php foreach ($rejected as $gp): ?>
			<div><?= $gp["reason"] ?> - <?= $gp["status"] ?></div>
		<?php endforeach; ?>

		<br><br>
		<a href="logout.php">Logout</a>

		</body>
		</html>

		<?php
}

	function studentLoginAPI() {
		session_start();
		header("Content-Type: application/json; charset=utf-8");

		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		$data = json_decode(file_get_contents("php://input"), true);

		if (!isset($data["email"], $data["password"])) {
			echo json_encode(["success" => false, "message" => "Email & Password required"]);
			exit;
		}

		$email = $data["email"];
		$password = $data["password"];

		$stmt = $conn->prepare("SELECT * FROM students WHERE email=? LIMIT 1");
		$stmt->bind_param("s", $email);
		$stmt->execute();
		$res = $stmt->get_result();

		if ($res->num_rows === 0) {
			echo json_encode(["success" => false, "message" => "Invalid credentials"]);
			exit;
		}

		$student = $res->fetch_assoc();

		if (!password_verify($password, $student["password"])) {
			echo json_encode(["success" => false, "message" => "Wrong password"]);
			exit;
		}

		$_SESSION["student_id"] = $student["id"];
		$_SESSION["student_name"] = $student["name"];

		echo json_encode([
			"success" => true,
			"message" => "Login successful",
			"redirect" => "index.php?module=User&action=studentDashboard"
		]);
		exit;
	}


	 function get_student_details(){
		
		global $connmysql;

		connecttodb("r", "nielitndu");
		$connmysql->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		
		if ($connmysql->connect_error) {
			error_log("Database connection failed: " . $connmysql->connect_error);
			echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
			exit();
		}

		// GET API: fetch student details
		if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['student_id'])) {
			$student_id = $connmysql->real_escape_string($_GET['student_id']);
			
			$stmt = $connmysql->prepare("
				SELECT 
					name, 
					email, 
					class, 
					semester, 
					mobile, 
					roll_no,
					gender, 
					parent_mobile,
					address
				FROM students 
				WHERE id = ?
			");
			if (!$stmt) {
				error_log("GET prepare failed: " . $connmysql->error);
				echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
				exit();
			}
			$stmt->bind_param("i", $student_id);
			$stmt->execute();
			$result = $stmt->get_result();
			$student = $result->fetch_assoc();
			$stmt->close();

			if ($student) {
				echo json_encode([
					'status' => 'success',
					'student' => $student,
					'message' => 'Student details fetched successfully'
				]);
			} else {
				echo json_encode([
					'status' => 'error',
					'message' => 'Student not found'
				]);
			}
			exit();
		}

		echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
	}
	
	 function update_request(){
		if(!isset($_SESSION['warden_id'])){
			header("Location: warden_login_form.php");
			exit();
		}

		$id = $_GET['id'];
		$action = $_GET['action'];

		$sql = "UPDATE gatepass_requests SET status='$action' WHERE id='$id'";
		$conn->query($sql);

		header("Location: warden_requests.php?status=Pending");
		exit();
	}


	 function updateProfile(){
		if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
			header('HTTP/1.1 200 OK');
			exit();
		}

		// Check database connection
		if ($conn->connect_error) {
			error_log("Database connection failed: " . $conn->connect_error);
			echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
			exit();
		}

		// POST API: Update student profile
		if ($_SERVER["REQUEST_METHOD"] == "POST") {
			$input = json_decode(file_get_contents('php://input'), true);
			if (isset($input['is_api'])) {
				error_log("Raw POST data: " . file_get_contents('php://input'));
				$data = $input;
				
				$student_id = $conn->real_escape_string($data['student_id'] ?? '');
				$name = trim($conn->real_escape_string($data['name'] ?? ''));
				$mobile = trim($conn->real_escape_string($data['mobile'] ?? ''));
				$roll_number = trim($conn->real_escape_string($data['roll_number'] ?? ''));
				$class = trim($conn->real_escape_string($data['class'] ?? ''));
				$semester = trim($conn->real_escape_string($data['semester'] ?? ''));
				$address = trim($conn->real_escape_string($data['address'] ?? ''));
				$email = trim($conn->real_escape_string($data['email'] ?? ''));

				// Validation
				if (empty($student_id) || empty($name) || empty($mobile) || empty($roll_number) || 
					empty($class) || empty($semester) || empty($address) || empty($email)) {
					error_log("Missing required fields for student_id: $student_id");
					echo json_encode(['status' => 'error', 'message' => 'Please fill all required fields']);
					exit();
				}

				// Check if student exists
				$stmt = $conn->prepare("SELECT id FROM students WHERE id = ?");
				if (!$stmt) {
					error_log("Student check prepare failed: " . $conn->error);
					echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
					exit();
				}
				$stmt->bind_param("s", $student_id);
				$stmt->execute();
				$result = $stmt->get_result();
				if ($result->num_rows == 0) {
					$stmt->close();
					error_log("Student not found for ID: $student_id");
					echo json_encode(['status' => 'error', 'message' => 'Student not found']);
					exit();
				}
				$stmt->close();

				// Update student profile
				$stmt = $conn->prepare(
					"UPDATE students SET name = ?, mobile = ?, roll_number = ?, class = ?, semester = ?, address = ?, email = ? WHERE id = ?"
				);
				if (!$stmt) {
					error_log("Update prepare failed: " . $conn->error);
					echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
					exit();
				}
				$stmt->bind_param("ssssssss", $name, $mobile, $roll_number, $class, $semester, $address, $email, $student_id);

				if ($stmt->execute()) {
					$stmt->close();
					echo json_encode(['status' => 'success', 'message' => 'Profile updated successfully']);
					exit();
				} else {
					error_log("Update failed: " . $stmt->error);
					echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $stmt->error]);
					$stmt->close();
					exit();
				}
			} else {
				echo json_encode(['status' => 'error', 'message' => 'Invalid API request']);
				exit();
			}
		}

		// Redirect non-API requests to login
		if (!isset($_SESSION['student_id'])) {
			header("Location: login_form.php");
			exit();
		}

	}

	protected function gatepassRequest(){
		if ($conn->connect_error) {
         error_log("Database connection failed: " . $conn->connect_error);
         header('Content-Type: application/json; charset=UTF-8');
         echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
         exit();
     }

     // -------------- API REQUESTS ------------------
     // GET API: fetch student's gate pass requests
     if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['student_id'])) {
         header('Content-Type: application/json; charset=UTF-8');
         header('Access-Control-Allow-Origin: *');
         $student_id = $conn->real_escape_string($_GET['student_id']);
         
         $stmt = $conn->prepare("
             SELECT 
                 g.id AS requestId, 
                 s.name AS studentName, 
                 s.email AS studentEmail, 
                 s.class, 
                 s.semester, 
                 s.mobile AS mobileNumber, 
                 g.reason, 
                 g.from_date AS date, 
                 g.out_time AS outTime, 
                 g.in_time AS inTime, 
                 g.outing_type, 
                 g.status, 
                 g.unique_code AS uniqueCode, 
                 g.approved_by AS approvedBy, 
                 g.rejection_reason AS rejectionReason, 
                 g.parent_confirmation, 
                 g.parent_mobile
             FROM gatepass_requests g
             JOIN students s ON g.student_id = s.id
             WHERE g.student_id = ?
             ORDER BY g.from_date DESC
         ");
         if (!$stmt) {
             error_log("GET prepare failed: " . $conn->error);
             echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
             exit();
         }
         $stmt->bind_param("i", $student_id);
         $stmt->execute();
         $result = $stmt->get_result();
         $gate_passes = [];
         while ($row = $result->fetch_assoc()) {
             $row['parent_confirmation'] = $row['parent_confirmation'] == 1;
             $gate_passes[] = $row;
         }
         $stmt->close();
         
         echo json_encode([
             'status' => 'success',
             'gate_passes' => $gate_passes,
             'message' => 'Gate passes fetched successfully'
         ]);
         exit();
     }

     // POST API: submit gate pass request
     if ($_SERVER["REQUEST_METHOD"] == "POST") {
         header('Content-Type: application/json; charset=UTF-8');
         header('Access-Control-Allow-Origin: *');
         $input = json_decode(file_get_contents('php://input'), true);
         if (isset($input['is_api'])) {
             error_log("Raw POST data: " . file_get_contents('php://input'));
             $data = $input;
             $student_id = $conn->real_escape_string($data['student_id'] ?? 0);

             // Fetch student gender
             $stmt = $conn->prepare("SELECT name, gender FROM students WHERE id = ?");
             if (!$stmt) {
                 error_log("Student fetch prepare failed: " . $conn->error);
                 echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
                 exit();
             }
             $stmt->bind_param("i", $student_id);
             $stmt->execute();
             $student = $stmt->get_result()->fetch_assoc();
             $stmt->close();
             
             if (!$student) {
                 error_log("Student not found for ID: $student_id");
                 echo json_encode(['status' => 'error', 'message' => 'Student not found']);
                 exit();
             }
             $gender = $student['gender'] ?? 'Male';

             // Collect and validate fields
             $reason = trim($conn->real_escape_string($data['reason'] ?? ''));
             $outing_type = trim($conn->real_escape_string($data['outing_type'] ?? ''));
             $from_date = trim($data['from_date'] ?? '');
             $to_date = trim($data['to_date'] ?? '');
             $out_time = trim($data['out_time'] ?? '');
             $in_time = trim($data['in_time'] ?? '');
             $parent_mobile = trim($conn->real_escape_string($data['parent_mobile'] ?? ''));
             $parent_confirmation = ($gender == 'Female') ? (isset($data['parent_confirmation']) && $data['parent_confirmation'] ? 1 : 0) : 1;

             // Validation
             if (empty($reason) || empty($outing_type) || empty($from_date) || empty($to_date) || empty($out_time) || empty($in_time)) {
                 error_log("Missing required fields for student_id: $student_id");
                 echo json_encode(['status' => 'error', 'message' => 'Please fill all required fields']);
                 exit();
             }
             if ($gender == 'Female' && !$parent_confirmation) {
                 error_log("Parent confirmation missing for female student: $student_id");
                 echo json_encode(['status' => 'error', 'message' => 'Parent confirmation is required for female students']);
                 exit();
             }
             if ($gender == 'Female' && empty($parent_mobile)) {
                 error_log("Parent mobile missing for female student: $student_id");
                 echo json_encode(['status' => 'error', 'message' => 'Parent mobile number is required for female students']);
                 exit();
             }

             // Insert gate pass request
             $stmt = $conn->prepare("
                 INSERT INTO gatepass_requests 
                 (student_id, reason, outing_type, from_date, to_date, out_time, in_time, status, parent_confirmation, parent_mobile, unique_code) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?, NULL)
             ");
             if (!$stmt) {
                 error_log("Insert prepare failed: " . $conn->error);
                 echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
                 exit();
             }
             $stmt->bind_param("isssssiss", $student_id, $reason, $outing_type, $from_date, $to_date, $out_time, $in_time, $parent_confirmation, $parent_mobile);

             if ($stmt->execute()) {
                 $request_id = $stmt->insert_id;
                 $stmt->close();
                 
                 // Notify warden
                 $wardenStmt = $conn->prepare("SELECT id FROM wardens WHERE gender = ? LIMIT 1");
                 if ($wardenStmt) {
                     $wardenStmt->bind_param("s", $gender);
                     $wardenStmt->execute();
                     $wardenResult = $wardenStmt->get_result();
                     if ($wardenResult->num_rows > 0) {
                         $warden = $wardenResult->fetch_assoc();
                         $warden_id = $warden['id'];
                         $notifyStmt = $conn->prepare("INSERT INTO notifications (user_type, user_id, message) 
                                                     VALUES ('warden', ?, ?)");
                         if ($notifyStmt) {
                             $notification_message = "New gate pass request from {$student['name']} (ID: $request_id)";
                             $notifyStmt->bind_param("is", $warden_id, $notification_message);
                             $notifyStmt->execute();
                             $notifyStmt->close();
                         }
                         $wardenStmt->close();
                     } else {
                         error_log("No warden found for gender: $gender");
                     }
                 }
                 
                 echo json_encode(['status' => 'success', 'message' => 'Gate pass request submitted successfully']);
                 exit();
             } else {
                 error_log("Insert failed: " . $stmt->error);
                 echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $stmt->error]);
                 $stmt->close();
                 exit();
             }
         }
     }

     // ------------- WEB REQUESTS -------------------
     if (!isset($_SESSION['student_id'])) {
         header("Location: login_form.php");
         exit();
     }

     $student_id = $_SESSION['student_id'];

     // Fetch student details
     $stmt = $conn->prepare("SELECT * FROM students WHERE id = ?");
     if (!$stmt) {
         error_log("Student fetch prepare failed: " . $conn->error);
         $_SESSION['message'] = "❌ Database error: Unable to fetch student details";
         header("Location: dashboard.php");
         exit();
     }
     $stmt->bind_param("i", $student_id);
     $stmt->execute();
     $student = $stmt->get_result()->fetch_assoc();
     $stmt->close();

     if (!$student) {
         error_log("Student not found for ID: $student_id");
         $_SESSION['message'] = "❌ Error: Student not found";
         header("Location: dashboard.php");
         exit();
     }
     $gender = $student['gender'] ?? 'Male';

     // Fetch gate pass requests
     $stmt = $conn->prepare("
         SELECT 
             id AS requestId, 
             reason, 
             from_date AS date, 
             out_time AS outTime, 
             in_time AS inTime, 
             outing_type, 
             status, 
             unique_code AS uniqueCode, 
             approved_by AS approvedBy, 
             rejection_reason AS rejectionReason, 
             parent_confirmation, 
             parent_mobile
         FROM gatepass_requests 
         WHERE student_id = ? 
         ORDER BY from_date DESC
     ");
     if (!$stmt) {
         error_log("Gate pass fetch prepare failed: " . $conn->error);
         $_SESSION['message'] = "❌ Database error: Unable to fetch gate pass requests";
     }
     $stmt->bind_param("i", $student_id);
     $stmt->execute();
     $gate_passes = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
     $stmt->close();

     if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($input['is_api'])) {
         $data = $_POST;
         $reason = trim($conn->real_escape_string($data['reason'] ?? ''));
         $outing_type = trim($conn->real_escape_string($data['outing_type'] ?? ''));
         $from_date = trim($data['from_date'] ?? '');
         $to_date = trim($data['to_date'] ?? '');
         $out_time = trim($data['out_time'] ?? '');
         $in_time = trim($data['in_time'] ?? '');
         $parent_mobile = trim($conn->real_escape_string($data['parent_mobile'] ?? ''));
         $parent_confirmation = ($gender == 'Female') ? (isset($data['parent_confirmation']) ? 1 : 0) : 1;

         // Validation
         if (empty($reason) || empty($outing_type) || empty($from_date) || empty($to_date) || empty($out_time) || empty($in_time)) {
             $_SESSION['message'] = "⚠ Please fill all required fields!";
         } elseif ($gender == 'Female' && !$parent_confirmation) {
             $_SESSION['message'] = "⚠ Parent confirmation is required for female students!";
         } elseif ($gender == 'Female' && empty($parent_mobile)) {
             $_SESSION['message'] = "⚠ Parent mobile number is required for female students!";
         } else {
             // Insert gate pass request
             $stmt = $conn->prepare("
                 INSERT INTO gatepass_requests 
                 (student_id, reason, outing_type, from_date, to_date, out_time, in_time, status, parent_confirmation, parent_mobile, unique_code) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?, NULL)
             ");
             if (!$stmt) {
                 error_log("Web insert prepare failed: " . $conn->error);
                 $_SESSION['message'] = "❌ Database error: Query preparation failed";
             } else {
                 $stmt->bind_param("isssssiss", $student_id, $reason, $outing_type, $from_date, $to_date, $out_time, $in_time, $parent_confirmation, $parent_mobile);
                 if ($stmt->execute()) {
                     $request_id = $stmt->insert_id;
                     // Notify warden
                     $wardenStmt = $conn->prepare("SELECT id FROM wardens WHERE gender = ? LIMIT 1");
                     if ($wardenStmt) {
                         $wardenStmt->bind_param("s", $gender);
                         $wardenStmt->execute();
                         $wardenResult = $wardenStmt->get_result();
                         if ($wardenResult->num_rows > 0) {
                             $warden = $wardenResult->fetch_assoc();
                             $warden_id = $warden['id'];
                             $notifyStmt = $conn->prepare("INSERT INTO notifications (user_type, user_id, message) 
                                                         VALUES ('warden', ?, ?)");
                             if ($notifyStmt) {
                                 $notification_message = "New gate pass request from {$student['name']} (ID: $request_id)";
                                 $notifyStmt->bind_param("is", $warden_id, $notification_message);
                                 $notifyStmt->execute();
                                 $notifyStmt->close();
                             }
                             $wardenStmt->close();
                         } else {
                             error_log("No warden found for gender: $gender");
                         }
                     }
                     $_SESSION['message'] = "✅ Gate pass request submitted successfully!";
                     header("Location: dashboard.php");
                     exit();
                 } else {
                     error_log("Web insert failed: " . $stmt->error);
                     $_SESSION['message'] = "❌ Database error: " . $stmt->error;
                 }
                 $stmt->close();
             }
         }
     }

     $message = $_SESSION['message'] ?? '';
     unset($_SESSION['message']);
     ?>

     <!DOCTYPE html>
     <html lang="en">
     <head>
         <meta charset="UTF-8">
         <meta name="viewport" content="width=device-width, initial-scale=1.0">
         <title>Gate Pass Request</title>
         <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
         <style>
             * {
                 margin: 0;
                 padding: 0;
                 box-sizing: border-box;
                 font-family: 'Inter', sans-serif;
             }

             body {
                 background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                 min-height: 100vh;
                 display: flex;
                 justify-content: center;
                 align-items: center;
                 padding: 20px;
             }

             .form-container {
                 max-width: 700px;
                 width: 100%;
                 background: #ffffff;
                 padding: 30px;
                 border-radius: 16px;
                 box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                 transition: transform 0.3s ease;
             }

             .form-container:hover {
                 transform: translateY(-5px);
             }

             h2 {
                 color: #1a3c6e;
                 text-align: center;
                 margin-bottom: 25px;
                 font-size: 24px;
                 font-weight: 600;
             }

             .student-info {
                 background: #f8fafc;
                 padding: 20px;
                 border-radius: 12px;
                 margin-bottom: 25px;
                 border-left: 4px solid #2d4a7c;
             }

             .student-info p {
                 margin: 8px 0;
                 font-size: 14px;
                 color: #333;
             }

             .student-info p strong {
                 color: #1a3c6e;
                 font-weight: 600;
             }

             .message {
                 text-align: center;
                 padding: 12px;
                 border-radius: 8px;
                 margin-bottom: 20px;
                 font-size: 14px;
                 font-weight: 500;
             }

             .success {
                 background: #e6ffed;
                 color: #2e7d32;
             }

             .error {
                 background: #ffebee;
                 color: #d32f2f;
             }

             .form-group {
                 margin-bottom: 20px;
             }

             label {
                 display: block;
                 margin-bottom: 8px;
                 font-weight: 500;
                 color: #1a3c6e;
                 font-size: 14px;
             }

             input, select, textarea {
                 width: 100%;
                 padding: 12px;
                 border: 1px solid #e0e4e9;
                 border-radius: 8px;
                 font-size: 14px;
                 color: #333;
                 background: #f8fafc;
                 transition: border-color 0.3s ease;
             }

             input:focus, select:focus, textarea:focus {
                 outline: none;
                 border-color: #2d4a7c;
                 background: #ffffff;
             }

             textarea {
                 resize: vertical;
                 min-height: 100px;
             }

             .checkbox {
                 display: flex;
                 align-items: center;
                 gap: 8px;
                 margin-bottom: 20px;
             }

             .checkbox input {
                 width: auto;
             }

             button {
                 width: 100%;
                 padding: 14px;
                 background: #2d4a7c;
                 color: white;
                 border: none;
                 border-radius: 8px;
                 font-size: 16px;
                 font-weight: 600;
                 cursor: pointer;
                 transition: background 0.3s ease, transform 0.2s ease;
             }

             button:hover {
                 background: #1b3156;
                 transform: translateY(-2px);
             }

             .back-link {
                 display: block;
                 text-align: center;
                 margin-top: 20px;
                 color: #2d4a7c;
                 text-decoration: none;
                 font-weight: 500;
                 font-size: 14px;
             }

             .back-link:hover {
                 text-decoration: underline;
             }

             @media (max-width: 480px) {
                 .form-container {
                     padding: 20px;
                 }

                 h2 {
                     font-size: 20px;
                 }

                 button {
                     font-size: 14px;
                 }
             }
         </style>
     </head>
     <body>
         <div class="form-container">
             <h2>📝 Gate Pass Request</h2>

             <?php if($message): ?>
                 <div class="message <?php echo strpos($message,'✅')!==false?'success':'error'; ?>">
                     <?php echo htmlspecialchars($message); ?>
                 </div>
             <?php endif; ?>

             <?php if($student): ?>
                 <div class="student-info">
                     <p><strong>Name:</strong> <?php echo htmlspecialchars($student['name'] ?? 'N/A'); ?></p>
                     <p><strong>Class:</strong> <?php echo htmlspecialchars($student['class'] ?? 'N/A'); ?></p>
                     <p><strong>Semester:</strong> <?php echo htmlspecialchars($student['semester'] ?? 'N/A'); ?></p>
                     <p><strong>Mobile:</strong> <?php echo htmlspecialchars($student['mobile'] ?? 'N/A'); ?></p>
                 </div>
             <?php endif; ?>

             <form method="POST">
                 <div class="form-group">
                     <label for="outing_type">Outing Type</label>
                     <select name="outing_type" id="outing_type" required>
                         <option value="">-- Select Outing Type --</option>
                         <option value="Local Outing">Local Outing</option>
                         <option value="Out of Station">Out of Station</option>
                     </select>
                 </div>

                 <div class="form-group">
                     <label for="reason">Reason</label>
                     <textarea name="reason" id="reason" placeholder="Enter reason for gate pass" required></textarea>
                 </div>

                 <?php if($gender=='Female'): ?>
                     <div class="checkbox">
                         <input type="checkbox" name="parent_confirmation" id="parent_confirmation">
                         <label for="parent_confirmation">Parent Confirmation (✔ confirm parents informed)</label>
                     </div>
                     <div class="form-group">
                         <label for="parent_mobile">Parent Mobile Number</label>
                         <input type="tel" name="parent_mobile" id="parent_mobile" placeholder="Enter parent's mobile number" pattern="[0-9]{10}" required>
                     </div>
                 <?php endif; ?>

                 <div class="form-group">
                     <label for="from_date">From Date</label>
                     <input type="date" name="from_date" id="from_date" required>
                 </div>

                 <div class="form-group">
                     <label for="to_date">To Date</label>
                     <input type="date" name="to_date" id="to_date" required>
                 </div>

                 <div class="form-group">
                     <label for="out_time">Out Time</label>
                     <input type="time" name="out_time" id="out_time" value="<?php echo date('H:i'); ?>" required>
                 </div>

                 <div class="form-group">
                     <label for="in_time">In Time</label>
                     <input type="time" name="in_time" id="in_time" required>
                 </div>

                 <button type="submit">Submit Request</button>
             </form>

             <a href="dashboard.php" class="back-link">⬅ Back to Dashboard</a>
         </div>
     </body>
     </html>
	<?php
	}

     function adminLogin(){

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		// Log request method for debugging
		error_log("Request Method: " . $_SERVER['REQUEST_METHOD']);
		error_log("Request Headers: " . json_encode(apache_request_headers()));
		if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
			header('Content-Type: application/json; charset=UTF-8');
			header('Access-Control-Allow-Origin: *');
			header('Access-Control-Allow-Methods: POST, OPTIONS');
			header('Access-Control-Allow-Headers: Content-Type');
			header('HTTP/1.1 200 OK');
			exit();
		}

		// Check database connection
		if ($conn->connect_error) {
			error_log("Database connection failed: " . $conn->connect_error);
			header('Content-Type: application/json; charset=UTF-8');
			http_response_code(500);
			echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
			exit();
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			// Handle API request
			$input = json_decode(file_get_contents('php://input'), true);
			if (isset($input['is_api'])) {
				header('Content-Type: application/json; charset=UTF-8');
				header('Access-Control-Allow-Origin: *');
				header('Access-Control-Allow-Methods: POST, OPTIONS');
				header('Access-Control-Allow-Headers: Content-Type');

				error_log("Raw POST data: " . file_get_contents('php://input'));

				$email = trim($conn->real_escape_string($input['email'] ?? ''));
				$password = $input['password'] ?? '';

				if (empty($email) || empty($password)) {
					http_response_code(400);
					echo json_encode(['status' => 'error', 'message' => 'Please provide both email and password']);
					exit();
				}

				try {
					$stmt = $conn->prepare("SELECT id, name, password, allowed_classes FROM admins WHERE email = ? LIMIT 1");
					if (!$stmt) {
						error_log("Query prepare failed: " . $conn->error);
						http_response_code(500);
						echo json_encode(['status' => 'error', 'message' => 'Database query preparation failed']);
						exit();
					}
					$stmt->bind_param("s", $email);
					$stmt->execute();
					$result = $stmt->get_result();

					if ($result->num_rows === 1) {
						$admin = $result->fetch_assoc();
						if (password_verify($password, $admin['password'])) {
							$_SESSION['admin_id'] = $admin['id'];
							$_SESSION['admin_name'] = $admin['name'];
							$allowed_classes = !empty($admin['allowed_classes']) ? json_decode($admin['allowed_classes'], true) : [];
							echo json_encode([
								'status' => 'success',
								'message' => 'Login successful',
								'admin_id' => $admin['id'],
								'admin_name' => $admin['name'],
								'allowed_classes' => $allowed_classes
							]);
						} else {
							http_response_code(401);
							echo json_encode(['status' => 'error', 'message' => 'Invalid email or password']);
						}
					} else {
						http_response_code(404);
						echo json_encode(['status' => 'error', 'message' => 'No admin account found']);
					}
					$stmt->close();
				} catch (Exception $e) {
					error_log("Database error: " . $e->getMessage());
					http_response_code(500);
					echo json_encode(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()]);
					exit();
				}
				exit();
			}

			// Handle HTML form submission
			header('Content-Type: text/html; charset=UTF-8');
			$email = trim($_POST['email'] ?? '');
			$password = $_POST['password'] ?? '';
			$error = '';

			if ($email === '' || $password === '') {
				$error = "Please enter both email and password.";
			} else {
				try {
					$stmt = $conn->prepare("SELECT id, name, password FROM admins WHERE email = ? LIMIT 1");
					if (!$stmt) {
						error_log("Query prepare failed: " . $conn->error);
						$error = "Database error.";
					} else {
						$stmt->bind_param("s", $email);
						$stmt->execute();
						$stmt->store_result();
						if ($stmt->num_rows === 1) {
							$stmt->bind_result($id, $name, $hash);
							$stmt->fetch();
							if (password_verify($password, $hash)) {
								$_SESSION['admin_id'] = $id;
								$_SESSION['admin_name'] = $name;
								header("Location: index.php?module=User&action=adminDashboard");
								exit();
							} else {
								$error = "Invalid email or password.";
							}
						} else {
							$error = "No admin account found.";
						}
						$stmt->close();
					}
				} catch (Exception $e) {
					error_log("Database error: " . $e->getMessage());
					$error = "Database error: " . $e->getMessage();
				}
			}
		} else {
			// Handle GET requests (render HTML login form)
			header('Content-Type: text/html; charset=UTF-8');
			$error = !empty($_SESSION['admin_id']) ? "You are already logged in." : '';
		}

		// Render HTML for non-API GET requests or POST with errors
		?>
		<!doctype html>
		<html>
		<head>
		<meta charset="utf-8">
		<title>Admin Login</title>
		<style>
			body {font-family: Arial; background: #f5f7fb;}
			.box {max-width: 420px; margin: 80px auto; padding: 22px; background: #fff; border-radius: 8px; box-shadow: 0 6px 18px rgba(0,0,0,.06);}
			input {width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 6px;}
			button {width: 100%; padding: 10px; background: #007bff; color: #fff; border: none; border-radius: 6px;}
			.error {color: #b00020; margin-bottom: 10px;}
		</style>
		</head>
		<body>
		<div class="box">
			<h2>Admin Login</h2>
			<?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
			<form method="post">
			<input type="email" name="email" placeholder="Admin email" required>
			<input type="password" name="password" placeholder="Password" required>
			<button type="submit">Login</button>
			</form>
		</div>
		</body>
		</html>
	<?php
	}

	 function adminDashboard(){

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		// Check if admin is logged in
		if(!isset($_SESSION['admin_id'])){
			header("Location: index.php");
			exit();
		}
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<title>Admin Dashboard</title>
			<style>
				body { font-family: Arial, sans-serif; background:#f4f4f4; }
				.container { max-width: 1000px; margin: 50px auto; background:#fff; padding: 20px; border-radius: 8px; }
				h2 { text-align:center; }
				.menu { display:flex; justify-content: space-around; margin-top:30px; }
				.menu a { padding:15px 25px; background:#007bff; color:#fff; text-decoration:none; border-radius:6px; font-weight:bold; }
				.menu a:hover { background:#0056b3; }
			</style>
		</head>
		<body>
		<div class="container">
			<h2>Welcome Admin</h2>
			<div class="menu">
				<a href="index.php?module=User&action=viewStudents">View Students</a>
				<a href="index.php?module=User&action=viewGatePasses">View Gate Passes</a>
				<a href="index.php?module=User&action=manageGuards">Manage Guards</a>
				<a href="../logout.php">Logout</a>
			</div>
		</div>
		</body>
		</html>
		<?php
	}

function viewStudents(){

    session_start();
    require_once "db.php";
    $db = new Database();
    $conn = $db->conn;

    // Check login
    if (!isset($_SESSION['admin_id'])) {
        header("Location: index.php?module=User&action=adminLogin");
        exit();
    }

    // Params
    $selected_class = $_GET['class'] ?? null;
    $selected_semester = $_GET['semester'] ?? null;

    try {

        /* ----------------------------------------------
            1️⃣ SHOW CLASS LIST (FIRST PAGE)
        ----------------------------------------------- */
        if (!$selected_class) {

            $result = $conn->query("SELECT DISTINCT class FROM students ORDER BY class ASC");
            $classes = [];
            while ($row = $result->fetch_assoc()) {
                $classes[] = $row['class'];
            }

            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <title>View Students</title>
                <style>
                    body { font-family: Arial; background:#f4f4f4; }
                    .container { max-width:900px; margin:40px auto; background:#fff; padding:20px;
                                border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1); }
                    h2 { text-align:center; }
                    ul { list-style:none; padding:0; }
                    li { margin:10px 0; }
                    a { color:#007bff; font-weight:bold; text-decoration:none; }
                    a:hover { text-decoration:underline; }
                </style>
            </head>
            <body>
            <div class="container">
                <h2>Student List - Select Class</h2>
                <ul>
                    <?php 
                    foreach ($classes as $class) {
                        echo "<li>
                                <a href='index.php?module=User&action=viewStudents&class=" . urlencode($class) . "'>
                                    " . htmlspecialchars($class) . "
                                </a>
                              </li>";
                    }
                    ?>
                </ul>
            </div>
            </body>
            </html>
            <?php
            return;
        }

        /* ----------------------------------------------
            2️⃣ SHOW SEMESTER LIST FOR SELECTED CLASS
        ----------------------------------------------- */
        if ($selected_class && !$selected_semester) {

            $stmt = $conn->prepare("SELECT DISTINCT semester FROM students WHERE class = ? ORDER BY semester ASC");
            $stmt->bind_param("s", $selected_class);
            $stmt->execute();
            $res = $stmt->get_result();

            $semesters = [];
            while ($row = $res->fetch_assoc()) {
                $semesters[] = $row['semester'];
            }
            $stmt->close();
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <title>View Students</title>
                <style>
                    body { font-family: Arial; background:#f4f4f4; }
                    .container { max-width:900px; margin:40px auto; background:#fff; padding:20px;
                                border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1); }
                    h2 { text-align:center; }
                    ul { list-style:none; padding:0; }
                    li { margin:10px 0; }
                    a { color:#007bff; font-weight:bold; text-decoration:none; }
                    a:hover { text-decoration:underline; }
                </style>
            </head>
            <body>
            <div class="container">
                <h2>Class: <?= htmlspecialchars($selected_class) ?> - Select Semester</h2>
                <ul>
                    <?php 
                    foreach ($semesters as $sem) {
                        echo "<li>
                                <a href='index.php?module=User&action=viewStudents&class=" . urlencode($selected_class) . "&semester=" . urlencode($sem) . "'>
                                    Semester " . htmlspecialchars($sem) . "
                                </a>
                              </li>";
                    }
                    ?>
                </ul>

                <p><a href="index.php?module=User&action=viewStudents">⬅ Back to Classes</a></p>

            </div>
            </body>
            </html>
            <?php
            return;
        }

        /* ----------------------------------------------
            3️⃣ SHOW STUDENTS FOR CLASS & SEMESTER
        ----------------------------------------------- */
        $stmt = $conn->prepare("
            SELECT name, email, roll_no AS rollNumber, student_mobile AS mobile, semester, class
            FROM students 
            WHERE class = ? AND semester = ?");
        $stmt->bind_param("ss", $selected_class, $selected_semester);
        $stmt->execute();
        $result = $stmt->get_result();

        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>View Students</title>
            <style>
                body { font-family: Arial; background:#f4f4f4; }
                .container { max-width:900px; margin:40px auto; background:#fff; padding:20px;
                            border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1); }
                table { width:100%; border-collapse:collapse; }
                th,td { padding:10px; border:1px solid #ddd; text-align:center; }
                th { background:#007bff; color:white; }
                a { text-decoration:none; color:#007bff; }
            </style>
        </head>
        <body>
        <div class="container">
            <h2>Class: <?= htmlspecialchars($selected_class) ?> | Semester: <?= htmlspecialchars($selected_semester) ?></h2>

            <table>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Roll No</th>
                    <th>Mobile</th>
                    <th>Semester</th>
                </tr>

                <?php 
                if ($result->num_rows === 0) {
                    echo "<tr><td colspan='5'>No students found</td></tr>";
                } else {
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>
                                <td>" . htmlspecialchars($row['name']) . "</td>
                                <td>" . htmlspecialchars($row['email']) . "</td>
                                <td>" . htmlspecialchars($row['rollNumber']) . "</td>
                                <td>" . htmlspecialchars($row['mobile']) . "</td>
                                <td>" . htmlspecialchars($row['semester']) . "</td>
                              </tr>";
                    }
                }
                ?>
            </table>

            <p><a href="index.php?module=User&action=viewStudents&class=<?= urlencode($selected_class) ?>">⬅ Back to Semesters</a></p>
            <p><a href="index.php?module=User&action=viewStudents">⬅ Back to Classes</a></p>
        </div>
        </body>
        </html>
        <?php

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }

}


	 function viewGatePasses(){

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
			if (!isset($_SESSION['admin_id'])) {
				http_response_code(401);
				echo json_encode([
					'status' => 'error',
					'message' => 'Unauthorized: Admin session required'
				]);
				exit();
			}

			// Get query parameters
			$selected_date = isset($_GET['date']) ? $_GET['date'] : null;

			try {
				if (!$selected_date) {
					// Fetch distinct dates
					$result = $conn->query("SELECT DISTINCT DATE(created_at) as request_date FROM gatepass_requests ORDER BY request_date DESC");
					$dates = [];
					while ($row = $result->fetch_assoc()) {
						$dates[] = $row['request_date'];
					}

					echo json_encode([
						'status' => 'success',
						'message' => empty($dates) ? 'No dates found' : 'Dates retrieved successfully',
						'data' => ['dates' => $dates]
					]);
				} else {
					// Fetch gate passes for the selected date
					$stmt = $conn->prepare("SELECT s.name, g.reason, g.from_date, g.to_date, g.status 
											FROM gatepass_requests g 
											JOIN students s ON g.student_id = s.id 
											WHERE DATE(g.created_at) = ?");
					$stmt->bind_param("s", $selected_date);
					$stmt->execute();
					$result = $stmt->get_result();
					$gatepasses = [];
					while ($row = $result->fetch_assoc()) {
						$gatepasses[] = $row;
					}
					$stmt->close();

					echo json_encode([
						'status' => 'success',
						'message' => empty($gatepasses) ? 'No gate passes found for this date' : 'Gate passes retrieved successfully',
						'data' => ['gatepasses' => $gatepasses]
					]);
				}
			} catch (Exception $e) {
				http_response_code(500);
				echo json_encode([
					'status' => 'error',
					'message' => 'Server error: ' . $e->getMessage()
				]);
			}

			$conn->close();
	}

	 function addGuard(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', 'C:/Apache24/logs/php_errors.log'); // Update path

		// Configure session settings
		ini_set('session.cookie_lifetime', 7 * 24 * 60 * 60); // 7 days
		ini_set('session.gc_maxlifetime', 7 * 24 * 60 * 60); // 7 days
		session_set_cookie_params([
			'lifetime' => 7 * 24 * 60 * 60, // 7 days
			'path' => '/',
			'domain' => '', // Set to your domain in production
			'secure' => true, // Use true in production with HTTPS
			'httponly' => true,
			'samesite' => 'None' // Required for cross-origin requests with credentials
		]);
		
		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		$response = array();

		try {
			// Check for admin session
			if (!isset($_SESSION['admin_id'])) {
				throw new Exception('Unauthorized: Admin session required', 401);
			}

			if ($_SERVER["REQUEST_METHOD"] !== "POST") {
				throw new Exception('Invalid request method: ' . $_SERVER["REQUEST_METHOD"], 405);
			}

			// Get JSON data from Flutter
			$data = json_decode(file_get_contents('php://input'), true);
			if (json_last_error() !== JSON_ERROR_NONE) {
				throw new Exception('Invalid JSON input: ' . json_last_error_msg(), 400);
			}

			$name = $data['name'] ?? '';
			$email = $data['email'] ?? '';
			$phone = $data['phone'] ?? '';
			$gender = $data['gender'] ?? '';
			$shift = $data['shift'] ?? '';
			$password = $data['password'] ?? '';

			// Validate input
			if (empty($name) || empty($email) || empty($phone) || empty($gender) || empty($shift) || empty($password)) {
				throw new Exception('All fields are required', 400);
			}

			// Validate email format
			if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
				throw new Exception('Invalid email format', 400);
			}

			// Validate gender
			if (!in_array($gender, ['Male', 'Female', 'Other'])) {
				throw new Exception('Invalid gender value', 400);
			}

			// Validate shift (example values, adjust as needed)
			if (!in_array($shift, ['Morning', 'Evening', 'Night'])) {
				throw new Exception('Invalid shift value', 400);
			}

			// Validate phone (basic regex for digits, adjust as needed)
			if (!preg_match('/^[0-9]{10,15}$/', $phone)) {
				throw new Exception('Invalid phone number format', 400);
			}

			// Check for duplicate email
			$stmt = $conn->prepare("SELECT id FROM security_guards WHERE email = ?");
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}
			$stmt->bind_param("s", $email);
			$stmt->execute();
			if ($stmt->get_result()->num_rows > 0) {
				$stmt->close();
				throw new Exception('Email already exists', 409);
			}
			$stmt->close();

			// Hash the password
			$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

			// Insert guard into database
			$stmt = $conn->prepare("INSERT INTO security_guards (name, email, phone, gender, shift, password) VALUES (?, ?, ?, ?, ?, ?)");
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}
			$stmt->bind_param("ssssss", $name, $email, $phone, $gender, $shift, $hashedPassword);
			if ($stmt->execute()) {
				$response['status'] = 'success';
				$response['message'] = 'Guard added successfully';
				http_response_code(201);
			} else {
				throw new Exception('Database error: ' . $conn->error, 500);
			}
			$stmt->close();
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
		}

		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		$conn->close();
		exit();
	}


	 function deleteGuard(){
		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
		if (!isset($_SESSION['admin_id'])) {
			http_response_code(401);
			echo json_encode([
				'status' => 'error',
				'message' => 'Unauthorized: Admin session required'
			]);
			exit();
		}

		try {
			$id = $_GET['id'] ?? '';
			if (empty($id)) {
				echo json_encode([
					'status' => 'error',
					'message' => 'Guard ID is required'
				]);
				exit();
			}

			$stmt = $conn->prepare("DELETE FROM security_guards WHERE id = ?");
			$stmt->bind_param("i", $id);
			if ($stmt->execute()) {
				echo json_encode([
					'status' => 'success',
					'message' => 'Guard deleted successfully'
				]);
			} else {
				echo json_encode([
					'status' => 'error',
					'message' => 'Error: ' . $conn->error
				]);
			}
			$stmt->close();
		} catch (Exception $e) {
			http_response_code(500);
			echo json_encode([
				'status' => 'error',
				'message' => 'Server error: ' . $e->getMessage()
			]);
		}

		$conn->close();
	}

	 function editGuard(){

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', 'C:/Apache24/logs/php_errors.log'); // Update path

		// Configure session settings
		ini_set('session.cookie_lifetime', 7 * 24 * 60 * 60); // 7 days
		ini_set('session.gc_maxlifetime', 7 * 24 * 60 * 60); // 7 days
		session_set_cookie_params([
			'lifetime' => 7 * 24 * 60 * 60, // 7 days
			'path' => '/',
			'domain' => '', // Set to your domain in production
			'secure' => true, // Use true in production with HTTPS
			'httponly' => true,
			'samesite' => 'None' // Required for cross-origin requests with credentials
		]);
		
	
		$response = array();

		try {
			// Check for admin session
			if (!isset($_SESSION['admin_id'])) {
				throw new Exception('Unauthorized: Admin session required', 401);
			}

			$method = $_SERVER["REQUEST_METHOD"];
			if ($method !== "GET" && $method !== "POST") {
				throw new Exception('Invalid request method: ' . $method, 405);
			}

			// Validate guard ID
			$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
			if ($id <= 0) {
				throw new Exception('Invalid guard ID', 400);
			}

			if ($method === "GET") {
				// Fetch guard details
				$stmt = $conn->prepare("SELECT id, name, email, phone, gender, shift FROM security_guards WHERE id = ?");
				if (!$stmt) {
					throw new Exception('Prepare failed: ' . $conn->error, 500);
				}
				$stmt->bind_param("i", $id);
				$stmt->execute();
				$result = $stmt->get_result();

				if ($result->num_rows === 0) {
					throw new Exception('Guard not found', 404);
				}

				$guard = $result->fetch_assoc();
				$response['status'] = 'success';
				$response['message'] = 'Guard retrieved successfully';
				$response['data'] = [
					'id' => (int)$guard['id'],
					'name' => $guard['name'],
					'email' => $guard['email'],
					'phone' => $guard['phone'],
					'gender' => $guard['gender'],
					'shift' => $guard['shift']
				];
				http_response_code(200);
				$stmt->close();
			} elseif ($method === "POST") {
				// Get JSON data from Flutter
				$data = json_decode(file_get_contents('php://input'), true);
				if (json_last_error() !== JSON_ERROR_NONE) {
					throw new Exception('Invalid JSON input: ' . json_last_error_msg(), 400);
				}

				$name = $data['name'] ?? '';
				$phone = $data['phone'] ?? '';
				$gender = $data['gender'] ?? '';

				// Validate input
				if (empty($name) || empty($phone) || empty($gender)) {
					throw new Exception('Name, phone, and gender are required', 400);
				}

				// Validate gender
				if (!in_array($gender, ['Male', 'Female', 'Other'])) {
					throw new Exception('Invalid gender value', 400);
				}

				// Validate phone (basic regex for 10-15 digits)
				if (!preg_match('/^[0-9]{10,15}$/', $phone)) {
					throw new Exception('Invalid phone number format', 400);
				}

				// Update guard details
				$stmt = $conn->prepare("UPDATE security_guards SET name = ?, phone = ?, gender = ? WHERE id = ?");
				if (!$stmt) {
					throw new Exception('Prepare failed: ' . $conn->error, 500);
				}
				$stmt->bind_param("sssi", $name, $phone, $gender, $id);
				if ($stmt->execute()) {
					if ($stmt->affected_rows === 0) {
						throw new Exception('Guard not found or no changes made', 404);
					}
					$response['status'] = 'success';
					$response['message'] = 'Guard updated successfully';
					http_response_code(200);
				} else {
					throw new Exception('Database error: ' . $conn->error, 500);
				}
				$stmt->close();
			}
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
		}

		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		$conn->close();
		exit();
	}

	 function manageGuard(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', 'C:/Apache24/logs/php_errors.log'); // Update path

		// Configure session settings
		ini_set('session.cookie_lifetime', 7 * 24 * 60 * 60); // 7 days
		ini_set('session.gc_maxlifetime', 7 * 24 * 60 * 60); // 7 days
		session_set_cookie_params([
			'lifetime' => 7 * 24 * 60 * 60, // 7 days
			'path' => '/',
			'domain' => '', // Set to your domain in production
			'secure' => true, // Use true in production with HTTPS
			'httponly' => true,
			'samesite' => 'None' // Required for cross-origin requests with credentials
		]);
		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		$response = array();

		try {
			// Check for admin session
			if (!isset($_SESSION['admin_id'])) {
				throw new Exception('Unauthorized: Admin session required', 401);
			}

			if ($_SERVER["REQUEST_METHOD"] !== "GET") {
				throw new Exception('Invalid request method: ' . $_SERVER["REQUEST_METHOD"], 405);
			}

			// Fetch all guards
			$result = $conn->query("SELECT id, name, email, phone, gender, shift FROM security_guards");
			if ($result === false) {
				throw new Exception('Database query failed: ' . $conn->error, 500);
			}

			$guards = [];
			while ($row = $result->fetch_assoc()) {
				$guards[] = [
					'id' => (int)$row['id'], // Ensure ID is integer
					'name' => $row['name'],
					'email' => $row['email'],
					'phone' => $row['phone'],
					'gender' => $row['gender'],
					'shift' => $row['shift']
				];
			}

			$response['status'] = 'success';
			$response['message'] = empty($guards) ? 'No guards found' : 'Guards retrieved successfully';
			$response['data'] = $guards;
			http_response_code(200);
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
		}

		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		$conn->close();
		exit();
	}

	 function adminLogout(){
		$is_api_request = isset($_GET['format']) && $_GET['format'] === 'json' || 
						(isset($_SERVER['CONTENT_TYPE']) && $_SERVER['CONTENT_TYPE'] === 'application/json');

		// Set content type for API requests
		if ($is_api_request) {
			header('Content-Type: application/json');
		}

		// Check admin session
		if (!isset($_SESSION['admin_id'])) {
			if ($is_api_request) {
				http_response_code(401);
				echo json_encode(['status' => 'error', 'message' => 'Unauthorized: No active session']);
				exit();
			} else {
				header("Location: ../login.php");
				exit();
			}
		}

		try {
			// Get admin_id from request body (for API) or session
			$admin_id = $_SESSION['admin_id'];
			if ($is_api_request) {
				$input = json_decode(file_get_contents('php://input'), true);
				if (isset($input['admin_id']) && !empty($input['admin_id'])) {
					$admin_id = $input['admin_id'];
				}
			}

			// Validate admin_id matches session
			if ($admin_id !== $_SESSION['admin_id']) {
				if ($is_api_request) {
					http_response_code(403);
					echo json_encode(['status' => 'error', 'message' => 'Forbidden: Invalid admin ID']);
					exit();
				} else {
					header("Location: index.php");
					exit();
				}
			}

			// Clear session data
			$_SESSION = [];
			if (ini_get("session.use_cookies")) {
				$params = session_get_cookie_params();
				setcookie(session_name(), '', time() - 42000,
					$params["path"], $params["domain"],
					$params["secure"], $params["httponly"]
				);
			}
			session_destroy();

			if ($is_api_request) {
				// Return JSON response for API
				http_response_code(200);
				echo json_encode(['status' => 'success', 'message' => 'Logged out successfully']);
			} else {
				// Redirect for web
				header("Location: ../login.php");
			}
		} catch (Exception $e) {
			if ($is_api_request) {
				http_response_code(500);
				echo json_encode(['status' => 'error', 'message' => 'Server error: ' . $e->getMessage()]);
			} else {
				?>
				<!DOCTYPE html>
				<html>
				<head>
					<title>Logout Error</title>
					<style>
						body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; }
						.container { max-width: 900px; margin: 40px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
						.error { color: red; text-align: center; }
					</style>
				</head>
				<body>
				<div class="container">
					<h2>Logout Error</h2>
					<p class="error">Error: <?= htmlspecialchars($e->getMessage()) ?></p>
					<p><a href="../login.php">Back to Login</a></p>
				</div>
				</body>
				</html>
				<?php
			}
		}

		$conn->close();
	}

	protected function guardLogin(){
		ob_start();
		header('Content-Type: application/json; charset=utf-8');
		header('Access-Control-Allow-Origin: *'); // Replace with Flutter app's origin
		header('Access-Control-Allow-Methods: POST, OPTIONS');
		header('Access-Control-Allow-Headers: Content-Type');
		header('Access-Control-Allow-Credentials: true');
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		// Handle CORS preflight request
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		// Session settings
		ini_set('session.cookie_lifetime', 7 * 24 * 60 * 60);
		ini_set('session.gc_maxlifetime', 7 * 24 * 60 * 60);
		session_set_cookie_params([
			'lifetime' => 7 * 24 * 60 * 60,
			'path' => '/',
			'domain' => '',
			'secure' => false, // For local testing; set to true in production with HTTPS
			'httponly' => true,
			'samesite' => 'Lax'
		]);
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
		$response = array();
		try {
			if ($_SERVER["REQUEST_METHOD"] !== "POST") {
				throw new Exception('Invalid request method: ' . $_SERVER["REQUEST_METHOD"], 405);
			}
			$raw_input = file_get_contents('php://input');
			error_log("Raw input: " . $raw_input);
			$data = json_decode($raw_input, true);
			if (json_last_error() !== JSON_ERROR_NONE) {
				throw new Exception('Invalid JSON input: ' . json_last_error_msg(), 400);
			}
			$email = $data['email'] ?? '';
			$password = $data['password'] ?? '';
			if (empty($email) || empty($password)) {
				throw new Exception('Email and password are required', 400);
			}
			if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
				throw new Exception('Invalid email format', 400);
			}
			$stmt = $conn->prepare("SELECT id, name, password FROM security_guards WHERE email = ?");
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}
			$stmt->bind_param("s", $email);
			$stmt->execute();
			$result = $stmt->get_result();
			if ($result->num_rows === 0) {
				$stmt->close();
				throw new Exception('Invalid email or password', 401);
			}
			$guard = $result->fetch_assoc();
			$stmt->close();
			if (!password_verify($password, $guard['password'])) {
				throw new Exception('Invalid email or password', 401);
			}
			$old_session_id = session_id();
			$_SESSION['guard_id'] = $guard['id'];

			// Add session cookie data to response
			$response['status'] = 'success';
			$response['message'] = 'Login successful';
			$response['guard_id'] = $guard['id'];
			$response['name'] = $guard['name'];
			$response['session_id'] = session_id(); // Include session ID
			$response['cookie'] = [
				'name' => session_name(), // Default is PHPSESSID
				'value' => session_id(),
				'expires' => time() + (7 * 24 * 60 * 60), // Match session.cookie_lifetime
				'path' => '/',
				'domain' => '',
				'secure' => false, // Match session cookie settings
				'httponly' => true,
				'samesite' => 'Lax'
			];
			http_response_code(200);
			$conn->close();
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
			$conn->close();
		}
		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		exit();
	}

	 function guardDashboard(){
		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
		if (!isset($_SESSION['guard_id'])) {
			header('Location: guard_login.html');
			exit();
		}
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<title>Guard Dashboard</title>
		</head>
		<body>
			<h2>Welcome, Security Guard!</h2>
			<p>Guard ID: <?php echo htmlspecialchars($_SESSION['guard_id']); ?></p>
			<a href="logout.php">Logout</a>
		</body>
		</html>   
	<?php
	}

	 function getGuardName(){

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		// Handle CORS preflight request
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		// Session settings
		ini_set('session.cookie_lifetime', 7 * 24 * 60 * 60);
		ini_set('session.gc_maxlifetime', 7 * 24 * 60 * 60);
		session_set_cookie_params([
			'lifetime' => 7 * 24 * 60 * 60,
			'path' => '/',
			'domain' => '', // Set to your domain in production
			'secure' => false, // Set to true in production with HTTPS
			'httponly' => true,
			'samesite' => 'None'
		]);
		
	
		$response = array();

		try {
			// Check for guard session
			if (!isset($_SESSION['guard_id'])) {
				throw new Exception('Unauthorized: Guard session required', 401);
			}

			// Check request method
			if ($_SERVER["REQUEST_METHOD"] !== "GET") {
				throw new Exception('Invalid request method: ' . $_SERVER["REQUEST_METHOD"], 405);
			}

			$guard_id = $_GET['guard_id'] ?? '';
			if (empty($guard_id) || !is_numeric($guard_id)) {
				throw new Exception('Invalid guard ID', 400);
			}

			$stmt = $conn->prepare("SELECT name FROM security_guards WHERE id = ?");
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}
			$stmt->bind_param("i", $guard_id);
			$stmt->execute();
			$result = $stmt->get_result();
			if ($result->num_rows === 0) {
				$stmt->close();
				throw new Exception('Guard not found', 404);
			}
			$guard = $result->fetch_assoc();
			$stmt->close();

			$response['status'] = 'success';
			$response['message'] = 'Guard name retrieved successfully';
			$response['data'] = ['name' => $guard['name']];
			http_response_code(200);
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
		}
		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		$conn->close();
		exit();
	}

	 function guardLogout(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		// Handle CORS preflight request
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		// Start session to access and destroy it
		session_start();

		$response = array();

		try {
			if ($_SERVER["REQUEST_METHOD"] !== "POST") {
				throw new Exception('Invalid request method: ' . $_SERVER["REQUEST_METHOD"], 405);
			}

			if (!isset($_SESSION['guard_id'])) {
				throw new Exception('Not authenticated', 401);
			}

			// Destroy session data
			$_SESSION = array(); // Clear all session variables
			if (ini_get("session.use_cookies")) {
				$params = session_get_cookie_params();
				setcookie(
					session_name(),
					'',
					time() - 42000, // Expire cookie immediately
					$params["path"],
					$params["domain"],
					$params["secure"],
					$params["httponly"]
				);
			}
			session_destroy(); // Destroy the session

			$response['status'] = 'success';
			$response['message'] = 'Logout successful';
			http_response_code(200);
		} catch (Exception $e) {
			$response['status'] = 'error';
			$response['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
		}
		ob_end_clean();
		echo json_encode($response, JSON_THROW_ON_ERROR);
		exit();
	}

	 function guardProfile(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		session_start();
		require_once "db.php";
		$db = new Database();
		$conn = $db->conn;

		$response = ['success' => false, 'data' => []];

		try {
			if (!isset($_SESSION['guard_id'])) {
				throw new Exception('Session expired', 401);
			}

			$guard_id = $_SESSION['guard_id'];
			$stmt = $conn->prepare("SELECT id, name, email FROM security_guards WHERE id = ?");
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}

			$stmt->bind_param('i', $guard_id);
			$stmt->execute();
			$result = $stmt->get_result();
			if ($result->num_rows === 0) {
				throw new Exception('Guard not found', 404);
			}

			$guard = $result->fetch_assoc();
			$response['success'] = true;
			$response['data']['profile'] = [
				'guard_id' => $guard['id'],
				'name' => $guard['name'],
				'email' => $guard['email']
			];
			http_response_code(200);
			$stmt->close();
			$conn->close();
		} catch (Exception $e) {
			$response['data']['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error: " . $e->getMessage());
			$conn->close();
		}

		ob_end_clean();
		echo json_encode($response);
		exit();
	}

	 function guardRecordEntries(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		// Handle preflight OPTIONS request
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			http_response_code(405);
			echo json_encode(['success' => false, 'data' => ['message' => 'Method not allowed']]);
			ob_end_clean();
			exit();
		}

		// Validate and start session
		$session_id = $_GET['session_id'] ?? '';
		if (empty($session_id)) {
			http_response_code(400);
			echo json_encode(['success' => false, 'data' => ['message' => 'Session ID required']]);
			error_log("Session ID missing in request");
			ob_end_clean();
			exit();
		}

		session_id($session_id);
		session_start();

		// Debug session data
		error_log("Session ID: $session_id");
		error_log("Session Data: " . print_r($_SESSION, true));
		error_log("Cookies: " . print_r($_COOKIE, true));

		// Check session variables
		if (!isset($_SESSION['guard_id'])) {
			http_response_code(401);
			echo json_encode(['success' => false, 'data' => ['message' => 'Unauthorized - Invalid session: guard_id missing']]);
			error_log("Unauthorized: guard_id not set in session");
			ob_end_clean();
			exit();
		}

		$guardId = $_SESSION['guard_id'];
		$guardName = $_SESSION['guard_name'] ?? 'Unknown Guard';

		// Initialize database connection
		include '../db.php';

		// Debug database connection
		if (!isset($conn) || !($conn instanceof mysqli)) {
			http_response_code(500);
			echo json_encode(['success' => false, 'data' => ['message' => 'Database connection failed: $conn is not initialized']]);
			error_log("Database connection failed: \$conn is not initialized");
			ob_end_clean();
			exit();
		}

		if ($conn->connect_error) {
			http_response_code(500);
			echo json_encode(['success' => false, 'data' => ['message' => 'Database connection failed: ' . $conn->connect_error]]);
			error_log("Database connection failed: " . $conn->connect_error);
			ob_end_clean();
			exit();
		}

		try {
			// Get JSON input
			$input = json_decode(file_get_contents('php://input'), true);
			error_log("Raw input: " . file_get_contents('php://input'));
			if (!$input || !isset($input['uniqueCode']) || !isset($input['entryType']) || !isset($input['guardId']) || 
				!isset($input['guardName']) || !isset($input['name']) || !isset($input['outTime']) || 
				!isset($input['inTime']) || !isset($input['date'])) {
				http_response_code(400);
				echo json_encode([
					'success' => false,
					'data' => ['message' => 'Missing required fields: uniqueCode, entryType, guardId, guardName, name, outTime, inTime, date']
				]);
				ob_end_clean();
				exit();
			}

			$uniqueCode = trim($input['uniqueCode']);
			$entryType = trim($input['entryType']);
			$inputGuardId = trim($input['guardId']);
			$guardName = trim($input['guardName']);
			$studentName = trim($input['name']);
			$class = trim($input['class'] ?? '');
			$semester = trim($input['semester'] ?? '');
			$mobile = trim($input['mobile'] ?? '');
			$reason = trim($input['reason'] ?? '');
			$outingType = trim($input['outingType'] ?? '');
			$outTime = trim($input['outTime']);
			$inTime = trim($input['inTime']);
			$parentConfirmation = isset($input['parentConfirmation']) ? ($input['parentConfirmation'] === 'Yes' ? 'Yes' : 'No') : 'No';
			$date = trim($input['date']);

			// Validate guard ID
			if ($inputGuardId != $guardId) {
				http_response_code(403);
				echo json_encode(['success' => false, 'data' => ['message' => 'Guard ID mismatch - Unauthorized']]);
				ob_end_clean();
				exit();
			}

			// Validate entry type
			if (!in_array($entryType, ['In Entry', 'Out Entry'])) {
				http_response_code(400);
				echo json_encode(['success' => false, 'data' => ['message' => 'Invalid entry type']]);
				ob_end_clean();
				exit();
			}

			// Validate time formats
			if ($outTime && !preg_match('/^([0-1][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$/', $outTime)) {
				http_response_code(400);
				echo json_encode(['success' => false, 'data' => ['message' => 'Invalid outTime format']]);
				ob_end_clean();
				exit();
			}
			if ($inTime && !preg_match('/^([0-1][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$/', $inTime)) {
				http_response_code(400);
				echo json_encode(['success' => false, 'data' => ['message' => 'Invalid inTime format']]);
				ob_end_clean();
				exit();
			}

			// Validate date format
			if ($date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
				http_response_code(400);
				echo json_encode(['success' => false, 'data' => ['message' => 'Invalid date format (YYYY-MM-DD)']]);
				ob_end_clean();
				exit();
			}

			// Check for duplicate entry
			$entryCheckStmt = $conn->prepare("SELECT id, entry_timestamp FROM gate_pass_entries WHERE unique_code = ? AND entry_type = ?");
			if (!$entryCheckStmt) {
				throw new Exception("Prepare failed for duplicate check: " . $conn->error);
			}
			$entryCheckStmt->bind_param("ss", $uniqueCode, $entryType);
			$entryCheckStmt->execute();
			$entryResult = $entryCheckStmt->get_result();
			$existingEntry = $entryResult->fetch_assoc();
			error_log("Duplicate check for uniqueCode=$uniqueCode, entryType=$entryType: Found " . $entryResult->num_rows . " rows");
			$entryCheckStmt->close();
			if ($existingEntry) {
				$timestamp = $existingEntry['entry_timestamp'] ?? 'unknown';
				http_response_code(409);
				$response = [
					'success' => false,
					'data' => [
						'message' => "$entryType already recorded",
						'conflict_id' => $existingEntry['id'],
						'recorded_at' => $timestamp
					]
				];
				error_log("409 Response: " . json_encode($response));
				echo json_encode($response);
				ob_end_clean();
				exit();
			}

			// Insert new entry
			$insertStmt = $conn->prepare("
				INSERT INTO gate_pass_entries (
					unique_code, entry_type, guard_id, guard_name, student_name, class,
					semester, mobile, reason, outing_type, out_time, in_time,
					parent_confirmation, request_date, entry_timestamp
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
			");
			if (!$insertStmt) {
				throw new Exception("Prepare failed for insert: " . $conn->error);
			}
			$outTimeValue = ($entryType === 'Out Entry' && $outTime) ? $outTime : null;
			$inTimeValue = ($entryType === 'In Entry' && $inTime) ? $inTime : null;
			$insertStmt->bind_param(
				"ssisssssssssss",
				$uniqueCode, $entryType, $guardId, $guardName, $studentName, $class,
				$semester, $mobile, $reason, $outingType, $outTimeValue, $inTimeValue,
				$parentConfirmation, $date
			);
			$success = $insertStmt->execute();
			$insertId = $insertStmt->insert_id;
			$insertStmt->close();
			if (!$success || $insertId <= 0) {
				throw new Exception("Insert failed: " . $conn->error);
			}

			// Success response
			$response = [
				'success' => true,
				'data' => [
					'message' => "$entryType recorded successfully",
					'data' => [
						'entry_id' => $insertId,
						'unique_code' => $uniqueCode,
						'entry_type' => $entryType,
						'guard_id' => $guardId,
						'guard_name' => $guardName,
						'student_name' => $studentName,
						'class' => $class,
						'semester' => $semester,
						'mobile' => $mobile,
						'reason' => $reason,
						'outing_type' => $outingType,
						'out_time' => $outTimeValue,
						'in_time' => $inTimeValue,
						'parent_confirmation' => $parentConfirmation,
						'request_date' => $date,
						'timestamp' => date('Y-m-d H:i:s')
					]
				]
			];
			http_response_code(200);
			error_log("Success Response: " . json_encode($response));
			echo json_encode($response);
			ob_end_clean();

		} catch (Exception $e) {
			http_response_code($e->getCode() ?: 500);
			$response = [
				'success' => false,
				'data' => ['message' => 'Server error: ' . $e->getMessage()]
			];
			error_log("Error in gate pass entry API: " . $e->getMessage());
			echo json_encode($response);
			ob_end_clean();
		} finally {
			if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
				$conn->close();
			}
			ob_end_flush();
		}
	}

	 function guardViewEntries(){
		ini_set('display_errors', 0);
		ini_set('display_startup_errors', 0);
		error_reporting(E_ALL);
		ini_set('error_log', __DIR__ . '/php_errors.log');

		// Handle preflight OPTIONS request
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			http_response_code(200);
			ob_end_clean();
			exit();
		}

		if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
			http_response_code(405);
			echo json_encode(['success' => false, 'data' => ['message' => 'Method not allowed']]);
			ob_end_clean();
			exit();
		}

		// Validate session ID
		$session_id = $_GET['session_id'] ?? '';
		if (empty($session_id)) {
			http_response_code(400);
			echo json_encode(['success' => false, 'data' => ['message' => 'Session ID required']]);
			error_log("Session ID missing in request");
			ob_end_clean();
			exit();
		}

		session_id($session_id);
		session_start();

		// Debug session data
		error_log("Session ID: $session_id");
		error_log("Session Data: " . print_r($_SESSION, true));
		error_log("Cookies: " . print_r($_COOKIE, true));

		// Check session variables
		if (!isset($_SESSION['guard_id'])) {
			http_response_code(401);
			echo json_encode(['success' => false, 'data' => ['message' => 'Unauthorized - Invalid session: guard_id missing']]);
			error_log("Unauthorized: guard_id not set in session");
			ob_end_clean();
			exit();
		}

		$guard_id = $_SESSION['guard_id'];

		// Initialize database connection
		include '../db.php';

		// Debug database connection
		if (!isset($conn) || !($conn instanceof mysqli)) {
			http_response_code(500);
			echo json_encode(['success' => false, 'data' => ['message' => 'Database connection failed: $conn is not initialized']]);
			error_log("Database connection failed: \$conn is not initialized");
			ob_end_clean();
			exit();
		}

		if ($conn->connect_error) {
			http_response_code(500);
			echo json_encode(['success' => false, 'data' => ['message' => 'Database connection failed: ' . $conn->connect_error]]);
			error_log("Database connection failed: " . $conn->connect_error);
			ob_end_clean();
			exit();
		}

		$response = ['success' => false, 'data' => []];

		try {
			$entry_type = isset($_GET['entry_type']) ? trim($_GET['entry_type']) : 'all';

			// Validate entry type
			if (!in_array($entry_type, ['all', 'In Entry', 'Out Entry'])) {
				http_response_code(400);
				echo json_encode(['success' => false, 'data' => ['message' => 'Invalid entry type']]);
				ob_end_clean();
				exit();
			}

			// Build query
			$query = "
				SELECT id, unique_code, entry_type, guard_id, guard_name, student_name, class, 
					semester, mobile, reason, outing_type, out_time, in_time, parent_confirmation, 
					request_date, entry_timestamp 
				FROM gate_pass_entries 
				WHERE guard_id = ?
			";
			$params = [$guard_id];
			$types = 'i';

			if ($entry_type !== 'all') {
				$query .= " AND entry_type = ?";
				$params[] = $entry_type;
				$types .= 's';
			}

			$stmt = $conn->prepare($query);
			if (!$stmt) {
				throw new Exception('Prepare failed: ' . $conn->error, 500);
			}

			// Bind parameters dynamically
			if (!empty($params)) {
				$stmt->bind_param($types, ...$params);
			}

			$stmt->execute();
			$result = $stmt->get_result();
			$entries = [];
			while ($row = $result->fetch_assoc()) {
				$entries[] = $row;
			}

			$response['success'] = true;
			$response['data']['entries'] = $entries;
			http_response_code(200);
			$stmt->close();
		} catch (Exception $e) {
			$response['data']['message'] = $e->getMessage();
			http_response_code($e->getCode() ?: 500);
			error_log("Error in gate pass view API: " . $e->getMessage());
		} finally {
			if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
				$conn->close();
			}
			ob_end_clean();
			echo json_encode($response);
			exit();
		}
	}

	 function validate(){
		error_reporting(E_ALL);
		ini_set('display_errors', 1);

		session_start();
		header('Content-Type: application/json');
		echo json_encode(['valid' => isset($_SESSION['guard_id'])]);
	}

}





