<?php
/**
 * Single-file PHP Login & Registration System
 * Assumptions:
 * - SQLite is used for zero-configuration database setup (stored locally as database.sqlite).
 * - Sessions are used to maintain user authentication state.
 * - Modern CSS with Tailwind CSS CDN and custom glassmorphism styles for high-end UX.
 */

session_start();

$db_file = __DIR__ . '/database.sqlite';
$error = '';
$success = '';

// Initialize SQLite database and users table
try {
    $pdo = new PDO('sqlite:' . $db_file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}

// Handle Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'register') {
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($name) || empty($email) || empty($password)) {
            $error = 'Please fill in all registration fields.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } else {
            $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $error = 'Email is already registered.';
            } else {
                $hashed_password = password_hash($password, PASSWORD_BCRYPT);
                $stmt = $pdo->prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
                if ($stmt->execute([$name, $email, $hashed_password])) {
                    $success = 'Registration successful! Please sign in.';
                } else {
                    $error = 'An error occurred during registration.';
                }
            }
        }
    } elseif ($action === 'login') {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $error = 'Please fill in all login fields.';
        } else {
            $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['user_email'] = $user['email'];
                header('Location: index.php');
                exit;
            } else {
                $error = 'Invalid email or password.';
            }
        }
    }
}

$is_logged_in = isset($_SESSION['user_id']);
$active_tab = ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'register') ? 'register' : 'login';
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Auth Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
        }
        .glass-card {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.4);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-indigo-900 via-purple-900 to-slate-900 min-h-screen flex items-center justify-center p-4">

    <!-- Background decorative blobs -->
    <div class="absolute top-1/4 left-1/4 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-pulse"></div>
    <div class="absolute bottom-1/4 right-1/4 w-72 h-72 bg-indigo-500 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-pulse"></div>

    <div class="w-full max-w-md relative z-10">
        <?php if ($is_logged_in): ?>
            <!-- Dashboard View -->
            <div class="glass-card rounded-3xl shadow-2xl p-8 text-center text-slate-800">
                <div class="w-20 h-20 bg-gradient-to-tr from-indigo-600 to-purple-600 rounded-2xl mx-auto flex items-center justify-center text-white text-3xl font-bold shadow-lg shadow-indigo-500/30 mb-6">
                    <?php echo strtoupper(substr($_SESSION['user_name'], 0, 1)); ?>
                </div>
                <h1 class="text-2xl font-bold text-slate-900 mb-2">Welcome back, <?php echo htmlspecialchars($_SESSION['user_name']); ?>!</h1>
                <p class="text-slate-600 mb-6 text-sm"><?php echo htmlspecialchars($_SESSION['user_email']); ?></p>
                
                <div class="bg-slate-50 border border-slate-200 rounded-2xl p-4 mb-6 text-left">
                    <div class="flex items-center text-sm text-slate-700 mb-2">
                        <i class="fa-solid fa-shield-halved text-indigo-600 mr-3"></i>
                        <span>Account Security: <strong>Protected</strong></span>
                    </div>
                    <div class="flex items-center text-sm text-slate-700">
                        <i class="fa-solid fa-clock text-indigo-600 mr-3"></i>
                        <span>Session Active</span>
                    </div>
                </div>

                <a href="index.php?action=logout" class="w-full block bg-gradient-to-r from-red-500 to-pink-600 text-white font-semibold py-3.5 px-6 rounded-2xl shadow-lg shadow-red-500/30 hover:opacity-90 transition duration-200 text-center">
                    <i class="fa-solid fa-arrow-right-from-bracket mr-2"></i> Sign Out
                </a>
            </div>
        <?php else: ?>
            <!-- Authentication Container -->
            <div class="glass-card rounded-3xl shadow-2xl p-8 text-slate-800">
                <div class="text-center mb-8">
                    <div class="inline-flex items-center justify-center w-12 h-12 bg-indigo-600 text-white rounded-xl shadow-md shadow-indigo-500/30 mb-3">
                        <i class="fa-solid fa-lock text-lg"></i>
                    </div>
                    <h2 class="text-2xl font-bold text-slate-900">Welcome Portal</h2>
                    <p class="text-sm text-slate-500 mt-1">Secure access to your dashboard</p>
                </div>

                <!-- Notifications -->
                <?php if (!empty($error)): ?>
                    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-2xl mb-6 text-sm flex items-center">
                        <i class="fa-solid fa-circle-exclamation mr-2 text-red-500"></i>
                        <span><?php echo htmlspecialchars($error); ?></span>
                    </div>
                <?php endif; ?>

                <?php if (!empty($success)): ?>
                    <div class="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-2xl mb-6 text-sm flex items-center">
                        <i class="fa-solid fa-circle-check mr-2 text-emerald-500"></i>
                        <span><?php echo htmlspecialchars($success); ?></span>
                    </div>
                <?php endif; ?>

                <!-- Tabs -->
                <div class="flex bg-slate-200/60 p-1 rounded-2xl mb-6">
                    <button type="button" id="tab-login" onclick="switchTab('login')" class="flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 <?php echo $active_tab === 'login' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'; ?>">Sign In</button>
                    <button type="button" id="tab-register" onclick="switchTab('register')" class="flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 <?php echo $active_tab === 'register' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'; ?>">Register</button>
                </div>

                <!-- Login Form -->
                <form id="form-login" method="POST" class="space-y-4 <?php echo $active_tab === 'register' ? 'hidden' : ''; ?>">
                    <input type="hidden" name="action" value="login">
                    <div>
                        <label class="block text-xs font-bold uppercase text-slate-600 mb-2">Email Address</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400"><i class="fa-regular fa-envelope"></i></span>
                            <input type="email" name="email" required class="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition" placeholder="you@example.com">
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-bold uppercase text-slate-600 mb-2">Password</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400"><i class="fa-regular fa-lock"></i></span>
                            <input type="password" name="password" required class="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition" placeholder="••••••••">
                        </div>
                    </div>
                    <button type="submit" class="w-full mt-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold py-3.5 px-6 rounded-2xl shadow-lg shadow-indigo-500/30 hover:opacity-90 transition duration-200">
                        Sign In <i class="fa-solid fa-arrow-right ml-2"></i>
                    </button>
                </form>

                <!-- Register Form -->
                <form id="form-register" method="POST" class="space-y-4 <?php echo $active_tab === 'login' ? 'hidden' : ''; ?>">
                    <input type="hidden" name="action" value="register">
                    <div>
                        <label class="block text-xs font-bold uppercase text-slate-600 mb-2">Full Name</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400"><i class="fa-regular fa-user"></i></span>
                            <input type="text" name="name" required class="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition" placeholder="John Doe">
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-bold uppercase text-slate-600 mb-2">Email Address</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400"><i class="fa-regular fa-envelope"></i></span>
                            <input type="email" name="email" required class="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition" placeholder="you@example.com">
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-bold uppercase text-slate-600 mb-2">Password</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-slate-400"><i class="fa-regular fa-lock"></i></span>
                            <input type="password" name="password" required class="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-2xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white transition" placeholder="••••••••">
                        </div>
                    </div>
                    <button type="submit" class="w-full mt-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold py-3.5 px-6 rounded-2xl shadow-lg shadow-indigo-500/30 hover:opacity-90 transition duration-200">
                        Create Account <i class="fa-solid fa-user-plus ml-2"></i>
                    </button>
                </form>
            </div>
        <?php endif; ?>
    </div>

    <script>
        /**
         * Switches between Login and Register views seamlessly.
         */
        function switchTab(tab) {
            const loginForm = document.getElementById('form-login');
            const registerForm = document.getElementById('form-register');
            const loginBtn = document.getElementById('tab-login');
            const registerBtn = document.getElementById('tab-register');

            if (tab === 'login') {
                loginForm.classList.remove('hidden');
                registerForm.classList.add('hidden');
                loginBtn.className = 'flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 bg-white text-slate-900 shadow-sm';
                registerBtn.className = 'flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 text-slate-600 hover:text-slate-900';
            } else {
                registerForm.classList.remove('hidden');
                loginForm.classList.add('hidden');
                registerBtn.className = 'flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 bg-white text-slate-900 shadow-sm';
                loginBtn.className = 'flex-1 py-2.5 text-sm font-semibold rounded-xl transition duration-200 text-slate-600 hover:text-slate-900';
            }
        }
    </script>
</body>
</html>