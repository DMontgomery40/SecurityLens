// Test file with various vulnerabilities

// CRITICAL: Eval execution
eval('console.log("hello")');

// CRITICAL: Command injection
const exec = require('child_process').exec;
exec('ls -la');

// HIGH: XSS vulnerability
document.innerHTML = userInput;

// MEDIUM: Memory leak potential
setInterval(() => {
  // Some operation
}, 1000);

// Test credentials
const password = "supersecret123";
const apiKey = "abcd1234";

// SQL query
const query = "SELECT * FROM users WHERE id = " + userId;
