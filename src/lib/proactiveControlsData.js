export const proactiveControlsData = {
  C4_ENCODE_ESCAPE: `
    <h3>C4: Encode and Escape Data</h3>
    <p>
      Encoding and escaping are defensive techniques meant to stop injection attacks. Encoding (changing to a different format) and Escaping (adding a character) make the data safe to handle.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Encode data before displaying it in the browser</li>
      <li>Use context-specific encoding when placing data in different HTML contexts</li>
      <li>Never accept actual HTML from untrusted sources</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
element.innerHTML = userInput;           // Direct injection
document.write(userData);                // Unsafe document write
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
element.textContent = userInput;         // Safe text assignment
const escaped = escapeHtml(userInput);   // HTML encoding
        </code>
      </pre>
    </div>
  `,

  C5_VALIDATE_INPUTS: `
    <h3>C5: Validate All Inputs</h3>
    <p>
      Input validation is a programming technique that ensures only properly formatted data enters the workflow. Proper validation helps prevent injection attacks, buffer overflows, and other security issues.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Validate input length, type, syntax, and business rules</li>
      <li>Use positive validation (whitelist) instead of negative (blacklist)</li>
      <li>Validate all data sources, not just user input</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
query("SELECT * FROM users WHERE id = " + userId);    // Direct SQL injection
exec("git " + userInput);                            // Command injection
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
// Parameterized queries
query("SELECT * FROM users WHERE id = ?", [userId]);

// Input validation
if (!isValidInput(userInput)) {
  throw new Error('Invalid input');
}
        </code>
      </pre>
    </div>
  `,

  C6_DIGITAL_IDENTITY: `
    <h3>C6: Implement Digital Identity</h3>
    <p>
      Digital Identity is the unique representation of a user (or other subject) as they engage in an online transaction. Authentication and session management are key aspects.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Use strong password hashing with salt</li>
      <li>Implement proper session management</li>
      <li>Consider multi-factor authentication</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
if (password === storedPassword) {     // Plain text comparison
  login(user);
}
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
// Strong hashing with salt
const salt = await bcrypt.genSalt(10);
const hash = await bcrypt.hash(password, salt);

// Secure comparison
const match = await bcrypt.compare(password, storedHash);
        </code>
      </pre>
    </div>
  `,

  C7_ACCESS_CONTROLS: `
    <h3>C7: Enforce Access Controls</h3>
    <p>
      Access Control (Authorization) is the process of granting or denying specific requests from a user, program, or process. Failure to implement proper access control can lead to unauthorized information disclosure, modification, or destruction.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Enforce access control checks consistently</li>
      <li>Deny by default, allow only if explicitly granted</li>
      <li>Implement role-based access control (RBAC)</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
// Client-side only checks
if(user.isAdmin) {             // Can be manipulated
  showAdminPanel();
}

// Direct object references
app.get('/api/docs/:id');      // No ownership check
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
// Server-side enforcement
await enforceUserPermissions(user, 'admin');
if(await canAccessDocument(user, docId)) {
  // Allow access
}
        </code>
      </pre>
    </div>
  `,

  C8_PROTECT_DATA: `
    <h3>C8: Protect Data Everywhere</h3>
    <p>
      Sensitive data requires extra protection, particularly when being transmitted or stored. This includes passwords, credit card numbers, health records, personal information, and business secrets.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Classify data by sensitivity level</li>
      <li>Apply controls based on classification</li>
      <li>Don't store sensitive data unnecessarily</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
const apiKey = "1234-abcd-5678";     // Hardcoded secrets
const config = {
  password: "secret123"              // Plaintext storage
};
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
// Environment variables
const apiKey = process.env.API_KEY;

// Secure storage
const password = await vault.getSecret('db_password');
        </code>
      </pre>
    </div>
  `,

  C10_ERROR_HANDLING: `
    <h3>C10: Handle All Errors and Exceptions</h3>
    <p>
      Error and exception handling is a critical security control. Proper handling prevents system crashes, denial of service, and information leakage through detailed error messages.
    </p>

    <h4>Key Aspects:</h4>
    <ul>
      <li>Catch and handle all exceptions</li>
      <li>Don't expose sensitive information in errors</li>
      <li>Log security-relevant errors appropriately</li>
    </ul>

    <h4>Implementation:</h4>
    <div class="example-block">
      <div class="example-label">❌ Vulnerable:</div>
      <pre class="code-block bad">
        <code>
// Detailed errors exposed to user
res.status(500).send(\`Database error: \${err}\`);

// Unhandled exceptions
getData(input);  // Could throw
        </code>
      </pre>

      <div class="example-label">✅ Safe:</div>
      <pre class="code-block good">
        <code>
try {
  await getData(input);
} catch (err) {
  // Log detailed error securely
  logger.error('Data fetch failed', { error: err });
  // Return safe message to user
  res.status(500).send('An error occurred');
}
        </code>
      </pre>
    </div>
  `
}; 