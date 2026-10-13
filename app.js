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
  database: 'db name where table is created in PG Admin', 
  password: 'KoK7o7NoC', 
  port: 5432,                
});

// Force clean DNS routing to prevent internal local operation timeouts
dns.setServers(['8.8.8.8', '1.1.1.1']); 
app.use(express.urlencoded({ extended: true }));

// 2. NODEMAILER SMTP TRANSPORTER CONFIGURATION
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'add Email from where otp is to be sent from', 
    pass: 'app password created from Google'   
  }
});

// Test connection to PostgreSQL server, then start listening on port 5000
pool.connect()
  .then(() => {
    console.log("🐘 Connected to PostgreSQL successfully!");
    app.listen(5000, () => console.log("🚀 Server running at http://localhost:5000"));
  })
  .catch((error) => console.error("Database connection failed:", error));

// EJS templating structures
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
               <p>This code will expire in 5 minutes. Ignore if you did not request this step.</p>`
    };
    await transporter.sendMail(mailOptions);
}

// --- CONTROLLER ROUTING MODULES ---

app.get('/', (request, response) => response.render('SignPage', { message: null, isSuccess: false }));
app.get('/login', (request, response) => response.render('LogPage', { message: null, isSuccess: false, username: '', password: '' }));
app.get('/forgot-password', (request, response) => response.render('ForgotPass', { message: null, isSuccess: false, email: '' }));

// Process Registration Workflow via POST
app.post('/username', async (request, response) => {
    const { username, email, password, otp, action } = request.body; 

    try {
        const findUser = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        const userExists = findUser.rows.length > 0;

        if (action === 'request_otp') {
            const targetHash = hashPassword(password);
            
            if (!userExists) {
                await pool.query('INSERT INTO users(username, email, password_hash) VALUES($1, $2, $3)', [username, email, targetHash]);
            } else {
                await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [targetHash, username]);
            }

            const otpCode = generateOTP();
            
            await pool.query(
                `INSERT INTO otps(email, otp_code, expires_at) VALUES($1, $2, NOW() + INTERVAL '5 minutes')
                 ON CONFLICT (email) DO UPDATE SET otp_code = $2, expires_at = NOW() + INTERVAL '5 minutes'`,
                [email, otpCode]
            );

            await sendOTPEmail(email, otpCode);
            return response.render('SignPage', { message: "OTP transmitted to your inbox! Valid for 5 minutes.", isSuccess: true, username, email, password });
        }

        if (action === 'verify_otp') {
            const otpCheck = await pool.query('SELECT * FROM otps WHERE email = $1 AND expires_at > NOW()', [email]);

            if (otpCheck.rows.length === 0) {
                return response.render('SignPage', { message: "OTP expired or not requested. Please request a new code.", isSuccess: false, username, email, password });
            }

            const activeOtpRecord = otpCheck.rows[0]; // Extracted single item correctly

            if (!otp || otp.trim() === '' || activeOtpRecord.otp_code !== otp) {
                return response.render('SignPage', { message: "Incorrect verification passcode. Check your inbox.", isSuccess: false, username, email, password });
            }

            await pool.query('DELETE FROM otps WHERE email = $1', [email]);
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

        if (action === 'request_otp') {
            const nextOTP = generateOTP();
            
            await pool.query(
                `INSERT INTO otps(email, otp_code, expires_at) VALUES($1, $2, NOW() + INTERVAL '5 minutes')
                 ON CONFLICT (email) DO UPDATE SET otp_code = $2, expires_at = NOW() + INTERVAL '5 minutes'`,
                [userRecord.email, nextOTP]
            );

            await sendOTPEmail(userRecord.email, nextOTP);
            return response.render('LogPage', { message: "Security passcode fired onto your inbox email. Valid for 5 minutes.", isSuccess: true, username, password });
        }

        if (action === 'verify_otp') {
            const otpCheck = await pool.query('SELECT * FROM otps WHERE email = $1 AND expires_at > NOW()', [userRecord.email]);

            if (otpCheck.rows.length === 0) {
                return response.render('LogPage', { message: "OTP expired or missing. Click 'Request OTP' again.", isSuccess: false, username, password });
            }

            const activeOtpRecord = otpCheck.rows[0]; 
            if (!otp || otp.trim() === '' || activeOtpRecord.otp_code !== otp) {
                return response.render('LogPage', { message: "Incorrect OTP passcode validation failure.", isSuccess: false, username, password });
            }

            await pool.query('DELETE FROM otps WHERE email = $1', [userRecord.email]);
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
            return response.render('ForgotPass', { message: "If this email exists in our records, a recovery code has been transmitted.", isSuccess: true, email });
        }

        const userRecord = result.rows[0]; 
        if (action === 'request_recovery_otp') {
            const recoveryOTP = generateOTP();
            
            await pool.query(
                `INSERT INTO otps(email, otp_code, expires_at) VALUES($1, $2, NOW() + INTERVAL '5 minutes')
                 ON CONFLICT (email) DO UPDATE SET otp_code = $2, expires_at = NOW() + INTERVAL '5 minutes'`,
                [email, recoveryOTP]
            );

            await sendOTPEmail(email, recoveryOTP);
            return response.render('ForgotPass', { message: "Recovery passcode dispatched! Valid for 5 minutes.", isSuccess: true, email });
        }

        if (action === 'verify_recovery_otp') {
            const otpCheck = await pool.query('SELECT * FROM otps WHERE email = $1 AND expires_at > NOW()', [email]);

            if (otpCheck.rows.length === 0) {
                return response.render('ForgotPass', { message: "Recovery passcode expired or missing. Please re-request.", isSuccess: false, email });
            }

            const activeOtpRecord = otpCheck.rows[0]; 
            if (!otp || otp.trim() === '' || activeOtpRecord.otp_code !== otp) {
                return response.render('ForgotPass', { message: "Incorrect verification code. Please try again.", isSuccess: false, email });
            }

            await pool.query('DELETE FROM otps WHERE email = $1', [email]);
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
const updatedHash = hashPassword(newPassword);
await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [updatedHash, email]);
return response.render('LogPage', { message: "Password updated successfully! Log in using your new credentials.", isSuccess: true, username: email, password: '' });
} catch (error) {
return response.render('ResetPass', { email, message: "System update failure: " + error.message });
}
});
app.get('/logout', (request, response) => response.redirect('/login'));