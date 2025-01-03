// test-vulnerabilities.js

// ---------------------------------------------------
// VULNERABLE CODE SAMPLES (EXPANDED)
// ---------------------------------------------------

// -------------------------------
// CRITICAL EXECUTION VULNERABILITIES
// -------------------------------

// CWE-95: Eval injection
function dangerousEval(userInput) {
  // Direct usage
  eval('console.log("Hello from eval!")');

  // Realistic scenario: user-provided code
  // e.g. imagine userInput = "alert('XSS')"
  const dynamicFunc = new Function('return ' + userInput)();
  return dynamicFunc;
}

// Another variant of eval injection
function partialEvalCase(req, res) {
  const data = req.body.script; // e.g. user sends "while(true) {}"
  // Maybe we do some naive check, but not enough
  if (data.includes('while')) {
    // We still do eval ironically
    eval(data);
  }
  res.send("Eval done");
}

// CWE-77: Command injection
const { exec, spawn } = require('child_process');
function dangerousExec(userInput) {
  // Basic example
  exec('ls -la ' + userInput);

  // Another example with template literal
  exec(`rm -rf ${userInput}`);
}

function dangerousSpawn(userInput) {
  // Using spawn
  spawn('mv', [userInput, '/tmp/backup']);
  // If userInput is something like "; rm -rf /", we might have trouble
}

// CWE-502: Unsafe deserialization
const { unserialize } = require('php-serialize');
function unsafeDeserialize(userInput) {
  // JSON parse can be safe-ish if we properly handle the data,
  // but let's say we do something naive here
  const userData = JSON.parse(userInput);

  // php-serialize is definitely risky if userInput is untrusted
  return unserialize(userInput);
}

// -------------------------------
// INJECTION VULNERABILITIES
// -------------------------------

// CWE-79: XSS vulnerability
function xssSnippet(userInput) {
  document.innerHTML = userInput;
  element.outerHTML = userInput;
  document.write(userInput);
  $('#element').html(userInput);
}

// Another XSS example (React, but dangerouslySetInnerHTML)
function xssReact(req, res) {
  const content = req.body.content; // user-provided
  const dangerousMarkup = { __html: content };
  // In real React code:
  // return <div dangerouslySetInnerHTML={dangerousMarkup} />;
  res.send("Simulated React XSS scenario");
}

// CWE-89: SQL injection
function sqlInjectionSnippet(username, userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query("INSERT INTO users VALUES('" + username + "')");
  return query;
}

// Another variant of SQLi using string concatenation
function dynamicSql(req, res) {
  const userId = req.query.userId;
  const sql = "DELETE FROM orders WHERE userId = '" + userId + "'";
  db.execute(sql);
  res.send("Deleted orders for user: " + userId);
}

// CWE-943: NoSQL injection
function noSqlSnippet(userInput) {
  db.users.find({ $where: "this.password === '" + userInput + "'" });
  collection.find({ username: { $regex: userInput } });
}

// Another NoSQL injection approach (Mongo .mapReduce or .aggregate)
function noSqlAgg(req, res) {
  collection.aggregate([
    { $match: { category: { $regex: req.body.category } } },
    { $group: { _id: '$category', total: { $sum: '$price' } } }
  ]);
  res.send("Aggregated data");
}

// -------------------------------
// AUTHENTICATION & CREDENTIALS
// -------------------------------

// CWE-798: Hardcoded credentials
const password = "supersecret123";
const apiKey = "abcd1234";
const secretKey = "my-secret-key";
const authToken = "Bearer abc123xyz";

// Another example of hardcoded
const HARDCODED_DB_PASS = "PASS_12345";
process.env.DB_PASS = HARDCODED_DB_PASS;

// CWE-306: Missing Authentication
function noAuthRoute(req, res) {
  // No check at all
  performAdminAction();
  res.send('Admin action performed with no auth');
}

// Another missing auth scenario
function openAccess(req, res) {
  // Should check if user is admin, but we don't
  handleCriticalOperation();
  res.send('Critical operation done, no auth');
}

// CWE-285: Improper Authorization
function improperAuthorization(req, res) {
  if (req.user) {
    // Only checks that a user is logged in, not that they’re an admin
    return handleAdminAction();
  }
  res.send('Not authorized');
}

// Another variant, checking isLoggedIn but not role
function partialAuthCheck(req, res) {
  if (req.session && req.session.isLoggedIn) {
    performDangerousAction();
  }
  res.send("Partial auth check, ignoring roles");
}

// -------------------------------
// ACCESS CONTROL
// -------------------------------

// CWE-639: IDOR
function getDocumentWithoutCheck(req, res) {
  return db.getDocument(req.params.id); // no access control verifying ownership
}

function updateUserNoOwnerCheck(req, res) {
  db.updateUser(req.params.userId, { role: 'admin' });
  res.send('Updated user role to admin');
}

// -------------------------------
// CRYPTOGRAPHIC ISSUES
// -------------------------------

// CWE-326: Weak cryptography
const crypto = require('crypto');
function weakCrypto() {
  const hash1 = crypto.createHash('md5');
  const hash2 = crypto.createHash('sha1');
  const weakHash = crypto.createHash('md5');
  return { hash1, hash2, weakHash };
}

// Another example of weak hashing or extremely low salt
function trivialHash(data) {
  const hashed = crypto.createHash('sha1').update(data).digest('hex');
  return hashed;
}

// CWE-327: Broken crypto (DES)
function brokenCryptoDES(key) {
  const cipher = crypto.createCipher('des', key);
  const decipher = crypto.createDecipher('des', key);
  return { cipher, decipher };
}

// Another broken example using RC4 or something outdated
function rc4Crypto(key, data) {
  const cipher = crypto.createCipher('rc4', key);
  return cipher.update(data, 'utf8', 'hex');
}

// -------------------------------
// ERROR HANDLING
// -------------------------------

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

// Another example returning raw error objects
function showDetailedError(e) {
  return JSON.stringify(e, Object.getOwnPropertyNames(e));
}

// -------------------------------
// MEMORY & RESOURCE ISSUES
// -------------------------------

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

// Another example: not closing DB connections
function noConnectionClose() {
  const conn = db.connect();
  conn.query("SELECT * FROM bigTable");
  // never calls conn.end() or similar
}

// CWE-23: Path traversal
function pathTraversal(userInput) {
  const filePath = "../" + userInput;
  const file = "../../" + userInput;
  const docPath = __dirname + '/' + userInput;
  return filePath;
}

// Another path traversal approach
function readFileTraversal(req, res) {
  const filename = req.query.file || 'default.txt';
  const data = fs.readFileSync(`../uploads/${filename}`, 'utf8');
  res.send(data);
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

// Another SSRF variant
function advancedSsrf(req, res) {
  const target = req.headers['x-custom-target'];
  if (target) {
    request.post(target, { form: req.body });
  }
  res.send('Posted data to user-specified target');
}

// -------------------------------
// SESSION MANAGEMENT
// -------------------------------

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

// Another session fixation style
function attachSessionManually(req, res) {
  const forcedSID = req.query.sid;
  req.sessionStore.set(forcedSID, { user: 'testUser' });
  res.send('Session attached manually');
}

// -------------------------------
// DATA PROTECTION
// -------------------------------

// CWE-200: Sensitive Data Exposure
function logSensitiveData() {
  console.log('Password:', password);
  console.log('API Key:', apiKey);
  console.log('Secret:', process.env.SECRET_KEY);
}

// Another example showing DB credentials in logs
function debugDbConnection() {
  console.log("DB connection string:", process.env.DB_URL);
}

// -------------------------------
// INSECURE TRANSMISSION
// -------------------------------

// CWE-319: Cleartext Transmission
function insecureTransmission() {
  fetch('http://api.example.com');
  fetch('http://payment.example.com');
}

// Another plain HTTP usage
function contactService() {
  axios.post('http://my-legacy-service.com/data', { test: true });
}

// CWE-614: Secure Flag Not Set on Sensitive Cookie
function insecureCookie(res) {
  res.cookie('sessionId', 'abc123', { httpOnly: false });
  res.cookie('authToken', 'xyz456', { secure: false });
}

// Another variant: missing HttpOnly entirely
function cookieNoHttpOnly(res) {
  res.cookie('adminToken', 'admin-12345', { secure: true });
}

// -------------------------------
// INPUT VALIDATION
// -------------------------------

// CWE-20: Improper Input Validation
function noValidation(req, res) {
  const userId = req.params.id; // no validation
  db.findUser(userId);
  res.send('Searched user: ' + userId);
}

// Another example with minimal checks
function partialValidation(req, res) {
  if (req.body.age) {
    // Not checking if it's numeric, negative, etc.
    db.users.updateAge(req.body.age);
  }
  res.send('Age updated');
}

// -------------------------------
// DEPENDENCY MANAGEMENT
// -------------------------------

// CWE-937: Using components with known vulns
const oldPackage = require('vulnerable-package');
import { riskyFunction } from 'outdated-library';

function callRisky() {
  oldPackage.legacyInit();
  riskyFunction();
}

function callOldPackage() {
  oldPackage.execDanger();
}

// Another scenario with old version in package.json
const pkgJSON = `
{
  "dependencies": {
    "vulnerable-package": "1.0.0",
    "outdated-library": "0.1.2"
  }
}
`;

// ---------------------------------------------------
// MOCK TESTS FOR EACH VULNERABILITY
// ---------------------------------------------------

// You have a good example test suite already. We'll just show it again with a few more lines
describe('Vulnerability Tests', () => {
  // We’ll simulate a “scanner” or use a dummy function that returns possible CWEs
  function dummyScan(codeString) {
    const found = [];

    // This is obviously simplistic. In real usage, you'd call your 
    // actual scanning library or regex engine over the entire codeString.
    // We'll illustrate a few new lines to catch variants.

    if (/eval\(|new\s+Function/.test(codeString)) found.push('95');   // CWE-95
    if (/exec\(|spawn\(/.test(codeString)) found.push('77');         // CWE-77
    if (/unserialize\(|php-serialize/.test(codeString)) found.push('502'); // CWE-502
    if (/document\.(innerHTML|write)|\.html\(/.test(codeString)) found.push('79'); // CWE-79
    if (/SELECT|INSERT\s+INTO\s+users|DELETE\s+FROM/.test(codeString)) found.push('89'); // CWE-89
    if (/\$where|\.find\s*\(\s*\{\s*\$regex/.test(codeString)) found.push('943'); // CWE-943
    if (/supersecret123|abcd1234|my-secret-key|Bearer abc123xyz|HARDCODED_DB_PASS/.test(codeString)) found.push('798'); // CWE-798
    if (/performAdminAction|handleAdminAction|handleCriticalOperation/.test(codeString) && !/authCheck|isAdmin/.test(codeString)) found.push('306'); // CWE-306
    if (/db\.getDocument\(req\.params\.id\)|db\.updateUser\(req\.params\.userId/.test(codeString)) found.push('639'); // CWE-639
    if (/createHash\(['"]md5|sha1|rc4/.test(codeString)) found.push('326'); // CWE-326 (or partially 327 if it's DES/rc4)
    if (/createCipher\(['"]des/.test(codeString)) found.push('327'); // DES usage
    if (/err\.stack|stack:\s*err\.stack/.test(codeString)) found.push('209'); // CWE-209
    if (/setInterval\(|new Array\(1000000\)|db\.connect\(\)/.test(codeString)) found.push('401'); // memory/connection leak
    if (/\.\.\/|\.\.\\/.test(codeString)) found.push('23'); // CWE-23
    if (/redirect\(req\.query\.returnUrl\)|window\.location\.href\s*=\s*req\.query\.returnUrl/.test(codeString)) found.push('601'); // open redirect
    if (/axios\.get\(req\.query\.url\)|fetch\(req\.body\.endpoint\)|request\(req\.params\.target\)/.test(codeString)) found.push('918'); // SSRF
    if (/req\.session\.id\s*=\s*req\.query\.sessionId|req\.session\.id\s*=\s*req\.body\.session/.test(codeString)) found.push('384'); // session fixation
    if (/console\.log\('Password:'|API Key:/.test(codeString) || /DB_URL/.test(codeString)) found.push('200'); // sensitive data
    if (/http:\/\/api\.example\.com|http:\/\/payment\.example\.com|http:\/\/my-legacy-service\.com/.test(codeString)) found.push('319'); // cleartext
    if (/res\.cookie\(.*secure:\s*false|httpOnly:\s*false/.test(codeString)) found.push('614'); // missing secure flag
    if (/db\.findUser\(req\.params\.id\)|updateAge\(req\.body\.age\)/.test(codeString)) found.push('20'); // no validation
    if (/vulnerable-package|outdated-library|dependencies.*vulnerable-package/.test(codeString)) found.push('937'); // known vulns

    return found;
  }

  // Test each function or code snippet
  it('CWE-95: Detect eval injection', () => {
    const code = dangerousEval.toString() + partialEvalCase.toString();
    expect(dummyScan(code)).toContain('95');
  });

  it('CWE-77: Detect command injection', () => {
    const code = dangerousExec.toString() + dangerousSpawn.toString();
    expect(dummyScan(code)).toContain('77');
  });

  it('CWE-502: Detect unsafe deserialization', () => {
    const code = unsafeDeserialize.toString();
    expect(dummyScan(code)).toContain('502');
  });

  it('CWE-79: Detect XSS', () => {
    const code = xssSnippet.toString() + xssReact.toString();
    expect(dummyScan(code)).toContain('79');
  });

  it('CWE-89: Detect SQL injection', () => {
    const code = sqlInjectionSnippet.toString() + dynamicSql.toString();
    expect(dummyScan(code)).toContain('89');
  });

  it('CWE-943: Detect NoSQL injection', () => {
    const code = noSqlSnippet.toString() + noSqlAgg.toString();
    expect(dummyScan(code)).toContain('943');
  });

  it('CWE-798: Detect hardcoded creds', () => {
    const code = password + apiKey + secretKey + authToken + HARDCODED_DB_PASS;
    expect(dummyScan(code)).toContain('798');
  });

  it('CWE-306: Detect missing auth', () => {
    const code = noAuthRoute.toString() + openAccess.toString();
    expect(dummyScan(code)).toContain('306');
  });

  it('CWE-639: Detect IDOR', () => {
    const code = getDocumentWithoutCheck.toString() + updateUserNoOwnerCheck.toString();
    expect(dummyScan(code)).toContain('639');
  });

  it('CWE-326 & 327: Detect weak/broken crypto', () => {
    const code = weakCrypto.toString() + trivialHash.toString() + brokenCryptoDES.toString() + rc4Crypto.toString();
    // We expect to find both 326 and 327 in this combined code
    const findings = dummyScan(code);
    expect(findings).toContain('326');  // MD5, SHA1
    expect(findings).toContain('327');  // DES
  });

  it('CWE-209: Detect sensitive error logging', () => {
    const code = sensitiveErrorLogging.toString() + showDetailedError.toString();
    expect(dummyScan(code)).toContain('209');
  });

  it('CWE-401: Detect memory leak & resource exhaustion', () => {
    const code = memoryLeak.toString() + resourceExhaustion.toString() + noConnectionClose.toString();
    expect(dummyScan(code)).toContain('401');
  });

  it('CWE-23: Detect path traversal', () => {
    const code = pathTraversal.toString() + readFileTraversal.toString();
    expect(dummyScan(code)).toContain('23');
  });

  it('CWE-601: Detect open redirect', () => {
    const code = openRedirect.toString();
    expect(dummyScan(code)).toContain('601');
  });

  it('CWE-918: Detect SSRF', () => {
    const code = serverSideRequestForgery.toString() + fetchUserAvatar.toString() + advancedSsrf.toString();
    expect(dummyScan(code)).toContain('918');
  });

  it('CWE-384: Detect session fixation', () => {
    const code = sessionFixation.toString() + attachSessionManually.toString();
    expect(dummyScan(code)).toContain('384');
  });

  it('CWE-200: Detect sensitive data exposure', () => {
    const code = logSensitiveData.toString() + debugDbConnection.toString();
    expect(dummyScan(code)).toContain('200');
  });

  it('CWE-319: Detect cleartext transmission', () => {
    const code = insecureTransmission.toString() + contactService.toString();
    expect(dummyScan(code)).toContain('319');
  });

  it('CWE-614: Detect unsecure cookie flags', () => {
    const code = insecureCookie.toString() + cookieNoHttpOnly.toString();
    expect(dummyScan(code)).toContain('614');
  });

  it('CWE-20: Detect improper input validation', () => {
    const code = noValidation.toString() + partialValidation.toString();
    expect(dummyScan(code)).toContain('20');
  });

  it('CWE-937: Detect usage of known-vulnerable packages', () => {
    const code = callRisky.toString() + callOldPackage.toString() + pkgJSON;
    expect(dummyScan(code)).toContain('937');
  });
});
