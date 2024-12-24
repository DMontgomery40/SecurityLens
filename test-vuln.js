// Test file with intentional vulnerabilities
const userInput = "malicious input";
eval(userInput);  // CRITICAL: eval execution

const password = "supersecret123";  // HIGH: hardcoded credentials

function processData(data) {
  document.innerHTML = data;  // HIGH: XSS vulnerability
}
