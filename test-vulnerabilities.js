// test-vulnerabilities.js
// A combined file that shows vulnerable code samples AND tests them with a mock scanner or regex approach

// ---------------------------------------------------
// VULNERABLE CODE SAMPLES
// ---------------------------------------------------

// CRITICAL EXECUTION VULNERABILITIES
// CWE-95: Eval injection
function dangerousEval(userInput) {
  eval('console.log("Hello from eval!")');
  // Realistic scenario: user-provided code
  return new Function('return ' + userInput)();
}

// CWE-77: Command injection
const { exec } = require('child_process');
function dangerousExec(userInput) {
  exec('ls -la ' + userInput);
  exec(`rm -rf ${userInput}`);
}

// CWE-502: Unsafe deserialization
const { unserialize } = require('php-serialize');
function unsafeDeserialize(userInput) {
  const userData = JSON.parse(userInput);   // JSON might be safe or not, depending on usage
  return unserialize(userInput);            // definitely a risk if input isn’t trusted
}

// INJECTION VULNERABILITIES
// CWE-79: XSS vulnerability
function xssSnippet(userInput) {
  document.innerHTML = userInput;
  element.outerHTML = userInput;
  document.write(userInput);
  $('#element').html(userInput);
}

// CWE-89: SQL injection
function sqlInjectionSnippet(username, userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query("INSERT INTO users VALUES('" + username + "')");
  return query;
}

// CWE-943: NoSQL injection
function noSqlSnippet(userInput) {
  db.users.find({ $where: "this.password === '" + userInput + "'" });
  collection.find({ username: { $regex: userInput } });
}

// AUTHENTICATION & CREDENTIALS
// CWE-798: Hardcoded credentials
const password = "supersecret123";
const apiKey = "abcd1234";
const secretKey = "my-secret-key";
const authToken = "Bearer abc123xyz";

// CWE-306: Missing Authentication
function noAuthRoute(req, res) {
  // No check at all
  performAdminAction();
  res.send('Admin action performed with no auth');
}

// CWE-285: Improper Authorization
function improperAuthorization(req, res) {
  if (req.user) {
    // Only checks that a user is logged in, not that they’re an admin
    return handleAdminAction();
  }
  res.send('Not authorized');
}

// ACCESS CONTROL
// CWE-639: IDOR
function getDocumentWithoutCheck(req, res) {
  return db.getDocument(req.params.id);  // no access control verifying ownership
}

// CRYPTOGRAPHIC ISSUES
// CWE-326: Weak cryptography
const crypto = require('crypto');
function weakCrypto() {
  const hash1 = crypto.createHash('md5');
  const hash2 = crypto.createHash('sha1');
  const weakHash = crypto.createHash('md5');
  return { hash1, hash2, weakHash };
}

// CWE-327: Broken crypto (DES)
function brokenCryptoDES(key) {
  const cipher = crypto.createCipher('des', key);
  const decipher = crypto.createDecipher('des', key);
  return { cipher, decipher };
}

// ERROR HANDLING
// CWE-209: Sensitive error info
function sensitiveErrorLogging(userData, req, res) {
  try {
    processUserData(userData);
  } catch (err) {
    console.error(err);
    res.json({ error: err.message });
    // Potentially exposes stack trace
    res.send({ stack: err.stack });
  }
}

// MEMORY & RESOURCE ISSUES
// CWE-401: Memory leak
function memoryLeak() {
  setInterval(() => {
    // Some operation that never clears references
  }, 1000);
}

// Resource exhaustion
function resourceExhaustion(req, res) {
  const largeArray = new Array(1000000).fill('x');
  res.send(`Allocated an array with ${largeArray.length} items`);
}

// CWE-23: Path traversal
function pathTraversal(userInput) {
  const filePath = "../" + userInput;
  const file = "../../" + userInput;
  const docPath = __dirname + '/' + userInput;
  // ...
  return filePath;
}

// CWE-601: Open redirect
function openRedirect(req, res) {
  res.redirect(req.query.returnUrl);
  window.location.href = req.query.returnUrl;
}

// SSRF
// CWE-918: SSRF
const axios = require('axios');
const fetch = require('node-fetch');
const request = require('request');

function serverSideRequestForgery(req, res) {
  axios.get(req.query.url);
  fetch(req.body.endpoint);
  request(req.params.target);
  return res.send('Requests sent');
}

function fetchUserAvatar(profileUrl) {
  return axios.get(profileUrl); // Potential SSRF if unvalidated
}

// SESSION MANAGEMENT
// CWE-384: Session Fixation
function sessionFixation(req) {
  req.session.id = req.query.sessionId;
  req.session.regenerate((err) => {
    if (!err) {
      // Overwrites new session ID with user-supplied data
      req.session.id = req.body.session;
    }
  });
}

// DATA PROTECTION
// CWE-200: Sensitive Data Exposure
function logSensitiveData() {
  console.log('Password:', password);
  console.log('API Key:', apiKey);
  console.log('Secret:', process.env.SECRET_KEY);
}

// INSECURE TRANSMISSION
// CWE-319: Cleartext Transmission
function insecureTransmission() {
  fetch('http://api.example.com');
  fetch('http://payment.example.com');
}

// CWE-614: Secure Flag Not Set on Sensitive Cookie
function insecureCookie(res) {
  res.cookie('sessionId', 'abc123', { httpOnly: false });
  res.cookie('authToken', 'xyz456', { secure: false });
}

// INPUT VALIDATION
// CWE-20: Improper Input Validation
function noValidation(req, res) {
  const userId = req.params.id; // no validation
  db.findUser(userId);
  res.send('Searched user: ' + userId);
}

// DEPENDENCY MANAGEMENT
// CWE-937: Using components with known vulns
const oldPackage = require('vulnerable-package');
import { riskyFunction } from 'outdated-library';

function callRisky() {
  oldPackage.legacyInit();
  riskyFunction();
}


// ---------------------------------------------------
// MOCK TESTS FOR EACH VULNERABILITY
// ---------------------------------------------------
describe('Vulnerability Tests', () => {
  // We’ll simulate a “scanner” or use a dummy function that returns possible CWEs
  function dummyScan(codeString) {
    // In real usage, you'd call your actual SecurityLens or any scanning library
    // Here we just return an array of CWEs we see in the string
    const found = [];

    if (/eval\(/.test(codeString) || /new\s+Function/.test(codeString)) found.push('95');
    if (/exec\(/.test(codeString)) found.push('77');
    if (/unserialize\(|\.parse\(/.test(codeString)) found.push('502');
    if (/document\.innerHTML|\.write|\.html\(/.test(codeString)) found.push('79');
    if (/SELECT|INSERT\s+INTO\s+users|DELETE\s+FROM/.test(codeString)) found.push('89');
    if (/\$where|\.find\(\{\s*\$regex/.test(codeString)) found.push('943');
    if (/supersecret123|abcd1234|my-secret-key|Bearer abc123xyz/.test(codeString)) found.push('798');
    if (/performAdminAction|handleAdminAction/.test(codeString) && !/authCheck|isAdmin/.test(codeString)) found.push('306');
    if (/getDocument\(req\.params\.id\)/.test(codeString)) found.push('639');
    if (/createHash\('md5'|'sha1'/.test(codeString)) found.push('326');
    if (/createCipher\('des'|createDecipher\('des'/.test(codeString)) found.push('327');
    if (/err\.stack/.test(codeString)) found.push('209');
    if (/setInterval\(|new Array\(1000000\)/.test(codeString)) found.push('401');
    if (/\.\.\/|\.\.\\/.test(codeString)) found.push('23');
    if (/redirect\(req\.query\.returnUrl\)/.test(codeString)) found.push('601');
    if (/axios\.get\(req\.query\.url\)|fetch\(req\.body\.endpoint\)/.test(codeString)) found.push('918');
    if (/req\.session\.id\s*=\s*req\.query\.sessionId/.test(codeString)) found.push('384');
    if (/console\.log\('Password:'/.test(codeString)) found.push('200');
    if (/http:\/\/api\.example\.com/.test(codeString)) found.push('319');
    if (/res\.cookie\(.*secure:\s*false\)/.test(codeString)) found.push('614');
    if (/db\.findUser\(req\.params\.id\)/.test(codeString)) found.push('20');
    if (/vulnerable-package|outdated-library/.test(codeString)) found.push('937');

    return found;
  }

  // We'll do test blocks for each vulnerability
  it('CWE-95: Detect eval injection', () => {
    const code = dangerousEval('userInput').toString();
    expect(dummyScan(code)).toContain('95');
  });

  it('CWE-77: Detect command injection', () => {
    const code = dangerousExec.toString();
    expect(dummyScan(code)).toContain('77');
  });

  it('CWE-502: Detect unsafe deserialization', () => {
    const code = unsafeDeserialize.toString();
    expect(dummyScan(code)).toContain('502');
  });

  it('CWE-79: Detect XSS', () => {
    const code = xssSnippet.toString();
    expect(dummyScan(code)).toContain('79');
  });

  it('CWE-89: Detect SQL injection', () => {
    const code = sqlInjectionSnippet.toString();
    expect(dummyScan(code)).toContain('89');
  });

  it('CWE-943: Detect NoSQL injection', () => {
    const code = noSqlSnippet.toString();
    expect(dummyScan(code)).toContain('943');
  });

  it('CWE-798: Detect hardcoded creds', () => {
    const code = password + apiKey + secretKey + authToken;
    expect(dummyScan(code)).toContain('798');
  });

  it('CWE-306: Detect missing auth', () => {
    const code = noAuthRoute.toString();
    expect(dummyScan(code)).toContain('306');
  });

  it('CWE-639: Detect IDOR', () => {
    const code = getDocumentWithoutCheck.toString();
    expect(dummyScan(code)).toContain('639');
  });

  it('CWE-326: Detect weak crypto', () => {
    const code = weakCrypto.toString();
    expect(dummyScan(code)).toContain('326');
  });

  it('CWE-327: Detect broken crypto (DES)', () => {
    const code = brokenCryptoDES.toString();
    expect(dummyScan(code)).toContain('327');
  });

  it('CWE-209: Detect sensitive error logging', () => {
    const code = sensitiveErrorLogging.toString();
    expect(dummyScan(code)).toContain('209');
  });

  it('CWE-401: Detect memory leak', () => {
    const code = memoryLeak.toString() + resourceExhaustion.toString();
    expect(dummyScan(code)).toContain('401');
  });

  it('CWE-23: Detect path traversal', () => {
    const code = pathTraversal.toString();
    expect(dummyScan(code)).toContain('23');
  });

  it('CWE-601: Detect open redirect', () => {
    const code = openRedirect.toString();
    expect(dummyScan(code)).toContain('601');
  });

  it('CWE-918: Detect SSRF', () => {
    const code = serverSideRequestForgery.toString() + fetchUserAvatar.toString();
    expect(dummyScan(code)).toContain('918');
  });

  it('CWE-384: Detect session fixation', () => {
    const code = sessionFixation.toString();
    expect(dummyScan(code)).toContain('384');
  });

  it('CWE-200: Detect sensitive data exposure', () => {
    const code = logSensitiveData.toString();
    expect(dummyScan(code)).toContain('200');
  });

  it('CWE-319: Detect cleartext transmission', () => {
    const code = insecureTransmission.toString();
    expect(dummyScan(code)).toContain('319');
  });

  it('CWE-614: Detect unsecure cookie flags', () => {
    const code = insecureCookie.toString();
    expect(dummyScan(code)).toContain('614');
  });

  it('CWE-20: Detect improper input validation', () => {
    const code = noValidation.toString();
    expect(dummyScan(code)).toContain('20');
  });

  it('CWE-937: Detect usage of known-vulnerable packages', () => {
    const code = callRisky.toString();
    expect(dummyScan(code)).toContain('937');
  });
});
