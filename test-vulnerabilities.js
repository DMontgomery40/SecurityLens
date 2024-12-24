// Test file with various vulnerabilities

// CRITICAL EXECUTION VULNERABILITIES
// CWE-95: Eval injection
eval('console.log("hello")');

// CWE-77: Command injection
const exec = require('child_process').exec;
exec('ls -la');

// CWE-502: Unsafe deserialization
const userData = JSON.parse(userInput);
const obj = unserialize(userInput);

// INJECTION VULNERABILITIES
// CWE-79: XSS vulnerability
document.innerHTML = userInput;

// CWE-89: SQL injection
const query = "SELECT * FROM users WHERE id = " + userId;

// CWE-943: NoSQL injection
db.users.find({ $where: "this.password === '" + userInput + "'" });
collection.find({ username: { $regex: userInput } });

// AUTHENTICATION & CREDENTIALS
// CWE-798: Hardcoded credentials
const password = "supersecret123";
const apiKey = "abcd1234";

// CWE-916: Weak password hashing
const passwordHash = crypto.createHash('md5').update(password).digest('hex');
bcrypt.hash(password, 10);  // Work factor too low

// ACCESS CONTROL
// CWE-639: Insecure Direct Object Reference
const userId = req.params.userId;
const documentId = req.query.docId;

// CRYPTOGRAPHIC ISSUES
// CWE-326: Weak cryptography
const dataHash = crypto.createHash('sha1').update(data).digest('hex');

// ERROR HANDLING
// CWE-209: Sensitive error info
try {
    // Some operation that might throw
    processUserData(userData);
} catch (err) {
    console.error(err);
    res.json({ error: err.message });
}

// MEMORY & RESOURCE ISSUES
// CWE-401: Memory leak
setInterval(() => {
    // Some operation
}, 1000);

// CWE-23: Path traversal
const filePath = "../" + userInput;
const file = "../../" + fileName;

// CWE-601: Open redirect
res.redirect(req.query.returnUrl);
window.location = userInput;

// NEW VULNERABILITIES

// CWE-918: Server-Side Request Forgery (SSRF)
// Making HTTP requests with user-supplied URLs
axios.get(req.query.url);
fetch(req.body.endpoint);
request(req.params.target);

// CWE-384: Session Fixation
// Setting session ID from user input
req.session.id = req.query.sessionId;
session.id = req.body.session;
