// Better test file with various vulnerabilities

// CRITICAL EXECUTION VULNERABILITIES
// CWE-95: Eval injection
eval('console.log("hello")');
new Function('return ' + userInput)();

// CWE-77: Command injection
const exec = require('child_process').exec;
exec('ls -la ' + userInput);
exec(`rm -rf ${userPath}`);

// CWE-502: Unsafe deserialization (Deserialization of Untrusted Data)
const userData = JSON.parse(userInput);
const obj = unserialize(userInput);

// INJECTION VULNERABILITIES
// CWE-79: XSS vulnerability
document.innerHTML = userInput;
element.outerHTML = data;
document.write(userContent);
$('#element').html(userInput);

// CWE-89: SQL injection
const query = "SELECT * FROM users WHERE id = " + userId;
db.query("INSERT INTO users VALUES('" + username + "')");

// CWE-943: NoSQL injection
db.users.find({ $where: "this.password === '" + userInput + "'" });
collection.find({ username: { $regex: userInput } });

// AUTHENTICATION & CREDENTIALS
// CWE-798: Hardcoded credentials
const password = "supersecret123";
const apiKey = "abcd1234";
const secretKey = "my-secret-key";
const authToken = "Bearer abc123xyz";

// CWE-916: Weak password hashing
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const passwordHash = crypto.createHash('md5').update(password).digest('hex');
bcrypt.hash(password, 10); // Work factor too low
const sha1Hash = crypto.createHash('sha1');

// ACCESS CONTROL
// CWE-639: Insecure Direct Object Reference (IDOR)
const userId = req.params.userId;
const documentId = req.query.docId;
const accountId = req.body.accountId;
const fileId = params.fileId;

// CRYPTOGRAPHIC ISSUES
// CWE-326: Weak cryptography
const hash1 = crypto.createHash('md5');
const hash2 = crypto.createHash('sha1');
const weakHash = require('crypto').createHash('md5');

// ERROR HANDLING
// CWE-209: Sensitive error info
try {
    processUserData(userData);
} catch (err) {
    console.error(err);
    res.json({ error: err.message });
    res.send({ stack: err.stack });
}

// MEMORY & RESOURCE ISSUES
// CWE-401: Memory leak
setInterval(() => {
    // Some operation that never clears
}, 1000);
setTimeout(function() {
    // Another operation that might not be cleared
}, 5000);

// CWE-23: Path traversal
const filePath = "../" + userInput;
const file = "../../" + fileName;
const docPath = __dirname + '/' + userPath;
const imagePath = './images/' + userSuppliedPath;

// CWE-601: Open redirect
res.redirect(req.query.returnUrl);
window.location = userInput;
window.location.href = redirectUrl;
location.href = userSuppliedUrl;

// SERVER-SIDE REQUEST FORGERY (SSRF)
// CWE-918: Making HTTP requests with user-supplied URLs
const axios = require('axios');
const fetch = require('node-fetch');
const request = require('request');
const http = require('http');
const https = require('https');

axios.get(req.query.url);
fetch(req.body.endpoint);
request(req.params.target);
http.get(userSuppliedUrl);
https.request(userInput);

// Additional SSRF example
function fetchUserAvatar(userProfileUrl) {
    return axios.get(userProfileUrl); // Potential SSRF if userProfileUrl is untrusted
}
fetchUserAvatar(req.query.profileUrl);

// SESSION MANAGEMENT
// CWE-384: Session Fixation
req.session.id = req.query.sessionId;
session.id = req.body.session;
sessionId = userInput;
req.session.identifier = req.query.session;

// Another session fixation example
req.session.regenerate(function(err) {
    if (!err) {
        req.session.id = userInput; // Overwrites new session ID with user-supplied data
    }
});

// DATA PROTECTION
// CWE-200: Sensitive Data Exposure
console.log('Password:', password);
console.log('API Key:', apiKey);
console.log('Secret:', process.env.SECRET_KEY);

// INSECURE TRANSMISSION
// CWE-319: Cleartext Transmission
const insecureUrl = 'http://api.example.com';
fetch('http://payment.example.com');
