const express = require('express');
const app = express();
const dns = require('node:dns');
const crypto = require('node:crypto');    
const nodemailer = require('nodemailer'); 
const { Pool } = require('pg');           

// 1. DATABASE CONNECTION CONFIGURATION
const pool = new Pool({
  user: 'postgres',          
  host: 'localhost',         
  database: 'auth_base', 
  password: 'KoK7o7NoC', 
  port: 5432,                
});

// Force Google and Cloudflare DNS to optimize email routing and avoid timeouts
dns.setServers(['8.8.8.8', '1.1.1.1']); 

// Middleware to parse incoming hidden POST body payload streams
app.use(express.urlencoded({ extended: true }));

// 2. NODEMAILER SMTP TRANSPORTER CONFIGURATION
// ⚠️ Update your email address and 16-character GOOGLE APP PASSWORD here!
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
  user: 'krishtidhark07@gmail.com',  
    pass: 'nmie chrz udqt pnrc'      
  }
});

// Establish the connection with your local PostgreSQL server, then start listening on port 5000
pool.connect()
  .then(() => {
    console.log("🐘 Connected to PostgreSQL successfully!");
    app.listen(5000, () => console.log("🚀 Server running at http://localhost:5000"));
  })
  .catch((error) => console.error("Database connection failed:", error));

// Configure EJS view layout directory structures
app.set('view engine', 'ejs');
app.set('views', './pages');

// --- HELPER SECURITY LOGIC FUNCTIONS ---
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(targetEmail, otp) {
    const mailOptions = {
        from: '"Alcheringa Security" <your-actual-email@gmail.com>',
        to: targetEmail,
        subject: 'Your Alcheringa System Verification Passcode',
        html: `<h3>System Authentication Check</h3>
               <p>Your security verification passcode sequence is: <b>${otp}</b></p>
               <p>If you did not request this step, ignore this transmission safely.</p>`
    };
    await transporter.sendMail(mailOptions);
}

// --- CONTROLLER ROUTING MODULES ---

// Initial Page Loaders (GET Requests)
app.get('/', (request, response) => {
    response.render('SignPage', { message: null, isSuccess: false });
});

app.get('/login', (request, response) => {
    response.render('LogPage', { message: null, isSuccess: false, username: '', password: '' });
});

app.get('/forgot-password', (request, response) => {
    response.render('ForgotPass', { message: null, isSuccess: false, email: '' });
});

// Process Registration Workflow via POST
app.post('/username', async (request, response) => {
    const { username, email, password, otp, action } = request.body; 

    try {
        const findQuery = 'SELECT * FROM users WHERE username = \$1 OR email = \$2';
        const findResult = await pool.query(findQuery, [username, email]);
        const userExists = findResult.rows.length > 0;
        const userRecord = findResult.rows[0];

        // BUTTON TYPE A: Blue "Request OTP" Trigger
        if (action === 'request_otp') {
            if (userExists && userRecord.is_verified) {
                return response.render('SignPage', { 
                    message: "This username or email address is already registered.", 
                    isSuccess: false, username, email, password 
                });
            }

            const targetHash = hashPassword(password);
            const otpCode = generateOTP();

            if (userExists) {
                const updateQuery = 'UPDATE users SET password_hash = \$1, otp_code = \$2, otp_sent = TRUE WHERE username = \$3';
                await pool.query(updateQuery, [targetHash, otpCode, username]);
            } else {
                const insertQuery = 'INSERT INTO users(username, email, password_hash, otp_code, otp_sent, is_verified) VALUES(\$1, \$2, \$3, \$4, TRUE, FALSE)';
                await pool.query(insertQuery, [username, email, targetHash, otpCode]);
            }

            await sendOTPEmail(email, otpCode);

            return response.render('SignPage', { 
                message: "OTP passcode transmitted to your email inbox! Please enter it below.", 
                isSuccess: true,
                username, email, password 
            });
        }

        // BUTTON TYPE B: Green "Verify & Complete" Trigger
        if (action === 'verify_otp') {
            if (!userExists || userRecord.otp_sent === false) {
                return response.render('SignPage', { 
                    message: "Please click the 'Request OTP' button first to generate a code.", 
                    isSuccess: false, username, email, password 
                });
            }

            if (!otp || otp.trim() === '' || userRecord.otp_code !== otp) {
                return response.render('SignPage', { 
                    message: "Incorrect or missing verification passcode. Check your inbox.", 
                    isSuccess: false,
                    username, email, password 
                });
            }

            const verifyQuery = 'UPDATE users SET is_verified = TRUE, otp_code = NULL, otp_sent = FALSE WHERE username = \$1';
            await pool.query(verifyQuery, [username]);

            return response.render('profile', { username: username, email: email });
        }

    } catch (error) {
        response.render('SignPage', { message: "Registration failed: " + error.message, isSuccess: false, username, email, password });
    }
});
// Process Login Workflow via POST
app.post('/loguser', async (request, response) => {
    const { username, password, otp, action } = request.body;
    const genericAuthError = "Incorrect username or password.";

    try {
        const findQuery = 'SELECT * FROM users WHERE username = $1 OR email = $1';
        const result = await pool.query(findQuery, [username]);

        if (result.rows.length === 0) {
            return response.render('LogPage', { message: genericAuthError, isSuccess: false, username, password });
        }

        const userRecord = result.rows[0];
        const incomingHash = hashPassword(password);

        if (incomingHash !== userRecord.password_hash) {
            return response.render('LogPage', { message: genericAuthError, isSuccess: false, username, password });
        }

        // BUTTON TYPE A: Blue "Request OTP" Trigger
        if (action === 'request_otp') {
            const nextOTP = generateOTP();
            const updateOtpQuery = 'UPDATE users SET otp_code = $1, otp_sent = TRUE WHERE username = $2';
            await pool.query(updateOtpQuery, [nextOTP, userRecord.username]);

            await sendOTPEmail(userRecord.email, nextOTP);

            return response.render('LogPage', { 
                message: "Security passcode fired onto your inbox email. Input it below to enter.", 
                isSuccess: true,
                username, password 
            });
        }

        // BUTTON TYPE B: Green "Verify & Complete" Trigger
        if (action === 'verify_otp') {
            if (userRecord.otp_sent === false) {
                return response.render('LogPage', { 
                    message: "Please click the 'Request OTP' button first to receive a passcode.", 
                    isSuccess: false, username, password 
                });
            }

            if (!otp || otp.trim() === '' || userRecord.otp_code !== otp) {
                return response.render('LogPage', { 
                    message: "Incorrect OTP passcode validation failure. Check your input.", 
                    isSuccess: false, 
                    username, password 
                });
            }

            const clearOtpQuery = 'UPDATE users SET otp_code = NULL, otp_sent = FALSE WHERE username = $1';
            await pool.query(clearOtpQuery, [userRecord.username]);

            return response.render('profile', { username: userRecord.username, email: userRecord.email });
        }

    } catch (error) {
        response.render('LogPage', { message: "System failure during validation processing.", isSuccess: false, username, password });
    }
});

// Process Password Recovery Entry Form Actions (POST Request)
app.post('/forgot-password', async (request, response) => {
    const { email, otp, action } = request.body;

    try {
        const findQuery = 'SELECT * FROM users WHERE email = $1';
        const result = await pool.query(findQuery, [email]);

        if (result.rows.length === 0) {
            // Obfuscation strategy against username/email tracking vulnerabilities
            return response.render('ForgotPass', { 
                message: "If this email exists in our records, a recovery code has been transmitted.", 
                isSuccess: true, email 
            });
        }

        const userRecord = result.rows[0];

        // SUB-ACTION A: Send Recovery Passcode
        if (action === 'request_recovery_otp') {
            const recoveryOTP = generateOTP();
            const updateQuery = 'UPDATE users SET otp_code = $1, otp_sent = TRUE WHERE email = $2';
            await pool.query(updateQuery, [recoveryOTP, email]);

            await sendOTPEmail(email, recoveryOTP);

            return response.render('ForgotPass', { 
                message: "Recovery passcode dispatched onto your inbox! Check and enter it below.", 
                isSuccess: true, email 
            });
        }

        // SUB-ACTION B: Match the Entered Recovery Code
        if (action === 'verify_recovery_otp') {
            if (userRecord.otp_sent === false) {
                return response.render('ForgotPass', { message: "Please click the 'Send Recovery OTP' button first.", isSuccess: false, email });
            }

            if (!otp || otp.trim() === '' || userRecord.otp_code !== otp) {
                return response.render('ForgotPass', { message: "Incorrect verification code. Please try again.", isSuccess: false, email });
            }

            // Clear temporary token trackers cleanly
            const resetFlagsQuery = 'UPDATE users SET otp_code = NULL, otp_sent = FALSE WHERE email = $1';
            await pool.query(resetFlagsQuery, [email]);

            // Forward verified user directly to the target Change Password form view card 
            return response.render('ResetPass', { email: email, message: null });
        }

    } catch (error) {
        response.render('ForgotPass', { message: "An unexpected error occurred: " + error.message, isSuccess: false, email });
    }
});

// Process Final Password Override Column Update (POST Request)
app.post('/update-password', async (request, response) => {
    const { email, newPassword, confirmPassword } = request.body;

    if (newPassword !== confirmPassword) {
        return response.render('ResetPass', { email, message: "Passwords do not match. Please re-enter them carefully." });
    }

    try {
        // Encrypt the fresh value using your senior's requested SHA-256 standard
        const updatedHash = hashPassword(newPassword);

        const updatePassQuery = 'UPDATE users SET password_hash = $1 WHERE email = $2';
        await pool.query(updatePassQuery, [updatedHash, email]);

        // Push the account back onto the main login card flashing a complete success status check
        return response.render('LogPage', { 
            message: "Password updated successfully! Log in using your new credentials.", 
            isSuccess: true, username: email, password: '' 
        });

    } catch (error) {
        return response.render('ResetPass', { email, message: "System update failure: " + error.message });
    }
});

// Clear temporary logic states and redirect back to login
app.get('/logout', (request, response) => {
    response.redirect('/login');
});
