// patterns.js
// Version: 2.0.0
// Last Audited: 2024-12-29
// CVSS Mapping: Included per pattern

const MAX_INPUT_LENGTH = 500000; // 500KB max input size
const MAX_CONTEXT_LINES = 5;     // Lines of context around matches

// Categories with CVSS mappings
export const patternCategories = {
  CRITICAL_EXECUTION: { id: '94', cvss: 9.8 },
  AUTHENTICATION: { id: '287', cvss: 9.1 },
  INJECTION: { id: '74', cvss: 9.0 },
  FILE_OPERATIONS: { id: '434', cvss: 8.8 },
  CRYPTO_ISSUES: { id: '310', cvss: 7.4 },
  MEMORY_BUFFER: { id: '119', cvss: 7.3 },
  DATA_PROTECTION: { id: '200', cvss: 7.5 },
  INPUT_VALIDATION: { id: '20', cvss: 6.5 },
  ERROR_HANDLING: { id: '389', cvss: 5.0 },
  ACCESS_CONTROL: { id: '264', cvss: 8.2 },
  RESOURCE_MGMT: { id: '399', cvss: 7.1 },
  SSRF: { id: '918', cvss: 8.6 },
  SESSION_MANAGEMENT: { id: '384', cvss: 8.0 },
  API_SECURITY: { id: '920', cvss: 8.3 },
  DEPENDENCY_MANAGEMENT: { id: '925', cvss: 7.5 }
};

// Pattern validation
function validatePattern(name, pattern) {
  // Check for potentially dangerous regex constructs
  const dangerous = /(a+)+$|\(\?<=|\(\?=.*\1/;
  if (dangerous.test(pattern.source)) {
    throw new Error(`Pattern ${name} uses potentially dangerous constructs`);
  }
  return true;
}

// Core pattern testing
function testPattern(name, pattern, input) {
  try {
    validatePattern(name, pattern);
    if (input.length > MAX_INPUT_LENGTH) {
      console.warn(`Input for ${name} exceeds recommended length of ${MAX_INPUT_LENGTH} bytes`);
    }
    return pattern.test(input);
  } catch (error) {
    console.error(`Pattern ${name} failed: ${error.message}`);
    return false;
  }
}

// Line number identification
function findMatchingLine(content, pattern) {
  try {
    const lines = content.split('\n');
    return lines.findIndex(line => pattern.test(line)) + 1 || null;
  } catch (error) {
    console.error('Line matching failed:', error);
    return null;
  }
}

// Context extraction
function extractContext(content, lineNumber) {
  try {
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - MAX_CONTEXT_LINES);
    const end = Math.min(lines.length, lineNumber + MAX_CONTEXT_LINES);
    return lines.slice(start, end).join('\n');
  } catch (error) {
    console.error('Context extraction failed:', error);
    return '';
  }
}

// Severity ordering
function severityOrder(severity) {
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  return order[severity.toUpperCase()] || 0;
}

// Consolidated Patterns
export const patterns = {
  // File Operation Patterns
  unsafeFileUpload: {
    pattern: /(?:\.upload\s*\(|multer\s*\(\s*{[^}]*}|\bupload\.single\s*\(|\.uploadFile\s*\()/,
    description: 'Potentially unsafe file upload configuration',
    severity: 'HIGH',
    category: patternCategories.FILE_OPERATIONS,
    subcategory: '434',
    cwe: '434',
    cvss: 8.8,
    framework: ['express', 'multer'],
    test: `
      // Should detect:
      app.post('/upload', upload.single('file'));
      multer({ dest: '/uploads' });
      // Should not detect:
      app.post('/upload', validateUpload, secureUpload);
    `
  },

  directoryTraversal: {
    pattern: /(?:require|import)\s*\(\s*(?:`|['"])\.[\/][^)`'"]+|\b(?:fs|path)\.(?:read|write|access|exists|stat|unlink|rmdir|mkdir)\s*\(\s*(?:`|['"])[^)`'"]*(?:\.\.\/)/,
    description: 'Potential directory traversal vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.FILE_OPERATIONS,
    subcategory: '23',
    cwe: '23',
    cvss: 9.1,
    test: `
      // Should detect:
      require('../' + userInput);
      fs.readFile('../../config.json');
      // Should not detect:
      require('./utils');
      fs.readFile('./config.json');
    `
  },

  unsafeFileExecution: {
    pattern: /(?:exec|spawn|fork)\s*\(\s*(?:`|['"])[^)`'"]*\.(?:sh|bash|zsh|py|pl|rb|php)/i,  // Unix executables
    description: 'Unsafe execution of file with dangerous extension',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '78',
    cwe: '78',
    cvss: 9.8,
    test: `
      // Should detect:
      exec('script.sh');
      spawn('./malicious.py');
      // Should not detect:
      exec('ls -la');
      spawn('node', ['script.js']);
    `
  },

  // Enhanced existing patterns with better regex
  evalExecution: {
    pattern: /(?:eval|new\s+Function|setTimeout|setInterval)\s*\(\s*(?:[^)]*\$\{|[^)]*\+|[^)]*\`|[^)]*(?<!['"])(?:req|res|user|input)\.)/,
    description: 'Dynamic code execution vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95',
    cwe: '95',
    cvss: 9.8,
    test: `
      // Should detect:
      eval(userInput);
      new Function(req.body.code);
      setTimeout('alert(' + input + ')', 1000);
      // Should not detect:
      eval('2 + 2');
      new Function('return 42');
    `
  },

  // Framework-specific patterns
  expressSecurityMisconfig: {
    pattern: /app\.(?:use\s*\(\s*(?:express\.static|bodyParser\.raw|cors\s*\(\s*\))|disable\s*\(\s*['"]x-powered-by['"]\))/,
    description: 'Potential Express.js security misconfiguration',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '16',
    cwe: '16',
    cvss: 6.5,
    framework: ['express'],
    test: `
      // Should detect:
      app.use(express.static(path));
      app.use(cors());
      // Should not detect:
      app.use(helmet());
      app.use(express.static(path, { strict: true }));
    `
  },

  // Enhanced dependency pattern
  vulnerableDependency: {
    pattern: /(?:require|import)\s*\(\s*['"](?:express|mongoose|mysql|pg|sqlite3|sequelize|typeorm|prisma|knex|mongodb)(?:@(?:\d+\.)?(?:\d+\.)?(?:\*|\d+))?['"]\)|import\s+(?:\*\s+as\s+)?(?:\w+)\s+from\s+['"](?:express|mongoose|mysql|pg|sqlite3|sequelize|typeorm|prisma|knex|mongodb)['"]/,
    description: 'Potential use of vulnerable package version',
    severity: 'HIGH',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '937',
    cwe: '937',
    cvss: 7.5,
    test: `
      // Should detect:
      require('express@4.16.1');
      import mongoose from 'mongoose@5.0.0';
      // Should not detect:
      require('safe-package');
      import { v4 } from 'uuid';
    `
  },

  // Execution Patterns
  evalExecution: {
    pattern: /eval\s*\([^)]*\)|new\s+Function\s*\(/,
    description: 'Dangerous code execution via eval() or Function constructor',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '95',
    cwe: '95'
  },
  commandInjection: {
    pattern: /child_process\.exec\s*\(|\.exec\s*\(|\.spawn\s*\(/,
    description: 'Potential command injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '77',
    cwe: '77'
  },
  unsafeDeserialization: {
    pattern: /(?:JSON\.parse|unserialize)\s*\([^)]*\)/,
    description: 'Unsafe deserialization of user-controlled data',
    severity: 'CRITICAL',
    category: patternCategories.CRITICAL_EXECUTION,
    subcategory: '502',
    cwe: '502'
  },

  // Authentication & Session Patterns
  missingAuth: {
    pattern: /authentication:\s*false|auth:\s*false|noAuth:\s*true|skipAuth/i,
    description: 'Authentication bypass or missing authentication',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '306',
    cwe: '306'
  },
  hardcodedCreds: {
    pattern: /(password|secret|key|token|credential)s?\s*[:=]\s*['"][^'"]+['"]/i,
    description: 'Hardcoded credentials detected',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798',
    cwe: '798'
  },
  hardcodedSecrets: {
    pattern: /(?:const|let|var)\s+(?:password|secret|key|token|credential)s?\s*=\s*['"][^'"]+['"]/i,
    description: 'Hardcoded secrets in code',
    severity: 'CRITICAL',
    category: patternCategories.AUTHENTICATION,
    subcategory: '798',
    cwe: '798',
    cvss: 9.1,
    test: `
      // Should detect:
      const password = "secret123";
      let apiKey = 'abcd1234';
      // Should not detect:
      const password = process.env.PASSWORD;
      let key = getKey();
    `
  },
  sessionFixation: {
    pattern: /(?:session|sess)\.id\s*=\s*(?:req\.(?:query|params|body)\.[^;\n]+|userInput)/i,
    description: 'Session fixation vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '384',
    cwe: '384'
  },
  insecureCookie: {
    pattern: /\.cookie\s*\([^)]+,\s*[^,]+,\s*{\s*(?!secure:|httpOnly:).*}\s*\)/,
    description: 'Cookie without secure flags',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '614',
    cwe: '614'
  },

  // Data Protection Patterns
  sensitiveData: {
    pattern: /(password|token|secret|key|credential|private)s?\s*=\s*[^;]+/i,
    description: 'Sensitive data exposure',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200',
    cwe: '200'
  },
  sensitiveDataExposure: {
    pattern: /console\.(log|error|debug|info)\s*\([^)]*(?:password|secret|key|token|credential)[^)]*\)/i,
    description: 'Sensitive data exposure in logs',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '200',
    cwe: '200'
  },
  insecureTransmission: {
    pattern: /https?:\/\/(?!localhost|127\.0\.0\.1)[^'"]+|ws:\/\/[^'"]+/,
    description: 'Potential insecure data transmission',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319',
    cwe: '319'
  },
  clearTextTransmission: {
    pattern: /(?:fetch|axios\.get|http\.get)\s*\(\s*['"]http:\/\/[^'"]+['"]\)/,
    description: 'Data transmitted over cleartext HTTP',
    severity: 'HIGH',
    category: patternCategories.DATA_PROTECTION,
    subcategory: '319',
    cwe: '319'
  },

  // Input Validation Patterns
  improperInputValidation: {
    pattern: /req\.(?:params|query|body)\.[a-zA-Z0-9_]+(?!\s*=|\s*\)|\s*,|\s*;)/,
    description: 'User input used without validation',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '20',
    cwe: '20'
  },

  // Dependency Management
  vulnerableDependency: {
    pattern: /(?:require|import)\s*\(\s*['"](?:express|mongoose|mysql|pg|sqlite3|sequelize|typeorm|prisma|knex|mongodb)['"]\).*(?:\d+\.\d+\.\d+)/,
    description: 'Potential use of vulnerable package version',
    severity: 'HIGH',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '937',
    cwe: '937'
  },

  // Injection Patterns
  sqlInjection: {
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
    description: 'Potential SQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '89',
    cwe: '89'
  },
  xssVulnerability: {
    pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\$\(.*\)\.html\s*\(/,
    description: 'Cross-site scripting vulnerability',
    severity: 'HIGH',
    category: patternCategories.INJECTION,
    subcategory: '79',
    cwe: '79'
  },
  noSqlInjection: {
    pattern: /\$where\s*:\s*['"]|\.find\s*\(\s*{[^}]*\$regex/,
    description: 'Potential NoSQL injection vulnerability',
    severity: 'CRITICAL',
    category: patternCategories.INJECTION,
    subcategory: '943',
    cwe: '943'
  },

  // Cryptography Patterns
  weakCrypto: {
    pattern: /crypto\.createHash\s*\(\s*['"]md5['"]\)|crypto\.createHash\s*\(\s*['"]sha1['"]\)/,
    description: 'Use of weak cryptographic hash function',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '326',
    cwe: '326'
  },
  insecureCryptoUsage: {
    pattern: /crypto\.createCipher\s*\(|crypto\.createDecipher\s*\(/,
    description: 'Use of deprecated cryptographic functions',
    severity: 'HIGH',
    category: patternCategories.CRYPTO_ISSUES,
    subcategory: '927',
    cwe: '927'
  },

  // Memory Patterns
  bufferIssue: {
    pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(/,
    description: 'Unsafe buffer allocation',
    severity: 'HIGH',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '119',
    cwe: '119'
  },
  memoryLeak: {
    pattern: /(setInterval|setTimeout)\s*\([^,]+,[^)]+\)/,
    description: 'Potential memory leak in timer/interval',
    severity: 'MEDIUM',
    category: patternCategories.MEMORY_BUFFER,
    subcategory: '401',
    cwe: '401'
  },

  // Error Handling Patterns
  sensitiveErrorInfo: {
    pattern: /catch\s*\([^)]*\)\s*{\s*(?:console\.(?:log|error)|res\.(?:json|send))\s*\([^)]*(?:err|error)/,
    description: 'Potential sensitive information in error messages',
    severity: 'MEDIUM',
    category: patternCategories.ERROR_HANDLING,
    subcategory: '209',
    cwe: '209'
  },

  // Access Control Patterns
  insecureDirectObjectRef: {
    pattern: /\b(?:user|account|file|document)Id\s*=\s*(?:params|query|body|req)\.[a-zA-Z_][a-zA-Z0-9_]*/,
    description: 'Potential Insecure Direct Object Reference (IDOR)',
    severity: 'HIGH',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '639',
    cwe: '639'
  },
  improperAuthorizationChecks: {
    pattern: /if\s*\(\s*(!?req\.user\.isAdmin\s*|\s*!req\.user\.hasPermission)/,
    description: 'Improper authorization checks allowing unauthorized access',
    severity: 'CRITICAL',
    category: patternCategories.ACCESS_CONTROL,
    subcategory: '306',
    cwe: '306'
  },

  // Input Validation Patterns
  pathTraversal: {
    pattern: /(?:\.\.\/|\.\.[\/])[^\/]*/,  // Unix paths only
    description: 'Potential path traversal vulnerability',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '23',
    cwe: '23'
  },
  unsanitizedInputUsage: {
    pattern: /process\.env\.[^;\n]+|config\.[a-zA-Z0-9_]+\s*=\s*req\.[a-zA-Z0-9_]+/,
    description: 'Unsanitized user input used in sensitive operations',
    severity: 'HIGH',
    category: patternCategories.INPUT_VALIDATION,
    subcategory: '932',
    cwe: '932'
  },

  // Resource Management Patterns
  openRedirect: {
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*=\s*(?:req\.(?:query|params|body)|['"]\s*\+)/,
    description: 'Potential open redirect vulnerability',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '601',
    cwe: '601'
  },
  resourceLeak: {
    pattern: /fs\.readFileSync\s*\(|fs\.writeFileSync\s*\(/,
    description: 'Potential resource leak due to synchronous file operations',
    severity: 'MEDIUM',
    category: patternCategories.RESOURCE_MGMT,
    subcategory: '399',
    cwe: '399'
  },

  // Session Management Patterns
  insecureSessionStorage: {
    pattern: /session\.cookie\s*=\s*[^;]+secure\s*:\s*false/i,
    description: 'Insecure session storage without secure flags',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '925',
    cwe: '925'
  },

  // Server-Side Request Forgery Patterns
  ssrfVulnerability: {
    pattern: /((axios|fetch|request)\s*\().*(req\.query|req\.params|req\.body)/,
    description: 'Potential SSRF vulnerability from user-supplied input in request calls',
    severity: 'CRITICAL',
    category: patternCategories.SSRF,
    subcategory: '918',
    cwe: '918'
  },

  // API Security Patterns
  insecureAPISetup: {
    pattern: /app\.use\s*\(\s*['"]\/api['"],\s*[^)]+\)/,
    description: 'Potential insecure API setup without proper authentication middleware',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '921',
    cwe: '921'
  },
  jwtInURL: {
    pattern: /jwt=.*[&?]/,
    description: 'JWT token present in URL instead of headers',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '922',
    cwe: '922'
  },
  tokenInURL: {
    pattern: /token=.*[&?]/,
    description: 'Authentication token present in URL parameters',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '923',
    cwe: '923'
  },
  badRateLimit: {
    pattern: /rateLimit\s*:\s*(?:\d+|\{[^}]+\})/,
    description: 'Potentially weak rate limiting configuration in API setup',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '924',
    cwe: '924'
  },
  missingCORS: {
    pattern: /app\.use\s*\(\s*['"]\/api['"],\s*cors\s*\(\s*\)\s*\)/,
    description: 'Missing or misconfigured CORS in API setup',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '925',
    cwe: '925'
  },
  insecureMiddleware: {
    pattern: /app\.use\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\)/,
    description: 'Insecure middleware setup allowing unauthorized access',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '926',
    cwe: '926'
  },
  insecureAPIStructure: {
    pattern: /(?:app\.(?:get|post|put|delete)|router\.(?:get|post|put|delete))\s*\(\s*['"]\/api\/[^'"]*[:*][^'"]*['"]/,
    description: 'API endpoint with potentially insecure parameter structure',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '20',
    cwe: '20'
  },
  massAssignment: {
    pattern: /(?:Object\.assign|{\s*\.\.\.req\.body\s*}|body\s*=\s*req\.body)/,
    description: 'Potential mass assignment vulnerability in API',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '915',
    cwe: '915'
  },
  inconsistentAuth: {
    pattern: /(?:app\.(?:get|post|put|delete)|router\.(?:get|post|put|delete))\s*\(\s*['"]\/api\/[^'"]+['"]\s*,\s*(?![^{]*authenticate)[^{]*=>/,
    description: 'Inconsistent authentication across API endpoints',
    severity: 'HIGH',
    category: patternCategories.API_SECURITY,
    subcategory: '306',
    cwe: '306'
  },
  verbTampering: {
    pattern: /app\.use\s*\(\s*['"]\/api\/[^'"]+['"]\s*,\s*\([^)]*\)\s*=>\s*{[^}]*}/,
    description: 'API endpoint vulnerable to HTTP verb tampering',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '434',
    cwe: '434'
  },
  responseLeakage: {
    pattern: /res\.(?:json|send)\s*\(\s*(?:{[^}]*error|err|error)[^)]*\)/,
    description: 'Potential sensitive information exposure in API error response',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '209',
    cwe: '209'
  },
  methodOverride: {
    pattern: /app\.use\s*\(\s*(?:methodOverride|['"]\/_method['"])/,
    description: 'Potentially dangerous HTTP method override',
    severity: 'MEDIUM',
    category: patternCategories.API_SECURITY,
    subcategory: '441',
    cwe: '441'
  },

  // Dependency Management Patterns
  outdatedDependency: {
    pattern: /"dependencies"\s*:\s*{[^}]*}/, // Simplistic pattern; enhanced in scanner logic
    description: 'Outdated dependencies detected in package.json',
    severity: 'MEDIUM',
    category: patternCategories.DEPENDENCY_MANAGEMENT,
    subcategory: '926',
    cwe: '926'
  }
};

// Recommendations
export const recommendations = {
  evalExecution: {
    recommendation: `
**Why it Matters**: Using \`eval()\` or the Function constructor can allow malicious 
code to run in your application, leading to data theft or system compromise.

**What to Do**:
1. **Avoid Dynamic Code**: Use safer alternatives (e.g., \`JSON.parse\` for JSON data).
2. **Sanitize Input**: If dynamic evaluation is unavoidable, carefully whitelist 
   valid inputs and reject anything unexpected.

**Example**:
Instead of:
\`\`\`javascript
eval(userInput);
\`\`\`
Do:
\`\`\`javascript
const parsed = JSON.parse(userInput); // with validation
\`\`\`
    `,
    references: [
      {
        title: 'CWE-95: Eval Injection',
        url: 'https://cwe.mitre.org/data/definitions/95.html'
      }
    ],
    cwe: '95'
  },
  commandInjection: {
    recommendation: `
**Why it Matters**: Command injection vulnerabilities let attackers run arbitrary
system commands, possibly taking full control of the server.

**What to Do**:
1. **Use \`execFile\`**: Prefer \`child_process.execFile()\` or \`spawn()\` with arguments, 
   instead of \`exec()\`.
2. **Validate User Input**: Reject or escape special characters (like ";", "&", "|").

**Example**:
Instead of:
\`\`\`javascript
exec('ls -la ' + userInput);
\`\`\`
Do:
\`\`\`javascript
execFile('ls', ['-la', userInput], callback);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-77: Command Injection',
        url: 'https://cwe.mitre.org/data/definitions/77.html'
      }
    ],
    cwe: '77'
  },
  missingAuth: {
    recommendation: `
**Why it Matters**: Skipping authentication leaves data wide open.

**What to Do**:
1. **Require Auth** on all sensitive endpoints.
2. **Use a robust auth system** or library.

**Example**:
Instead of:
\`\`\`javascript
app.get("/admin", (req, res) => { ... });
\`\`\`
Do:
\`\`\`javascript
app.get("/admin", requireAuth, (req, res) => { ... });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-306: Missing Authentication',
        url: 'https://cwe.mitre.org/data/definitions/306.html'
      }
    ],
    cwe: '306'
  },
  hardcodedCreds: {
    recommendation: `
**Why it Matters**: Hardcoded credentials can be easily discovered and exploited.

**What to Do**:
1. **Use Environment Variables** or secret managers.
2. **Rotate Credentials** if leaked.
3. **Implement Secret Detection** hooks to block commits with secrets.

**Example**:
Instead of:
\`\`\`javascript
const password = "supersecret123";
\`\`\`

Do:
\`\`\`javascript
const password = process.env.DB_PASSWORD;
\`\`\`
    `,
    references: [
      {
        title: 'CWE-798: Use of Hard-coded Credentials',
        url: 'https://cwe.mitre.org/data/definitions/798.html'
      },
      {
        title: 'OWASP Secure Configuration Guide',
        url: 'https://owasp.org/www-project-secure-configuration-guide/'
      }
    ],
    cwe: '798'
  },
  sqlInjection: {
    recommendation: `
**SQL Injection Vulnerability**

**Why it Matters**: SQL injection can allow attackers to read, modify, or delete database data, or even execute admin commands.

**What to Do**:
1. **Use Parameterized Queries**: Never concatenate user input into SQL strings
2. **Input Validation**: Validate each field individually
3. **Use ORMs**: Prefer ORM frameworks that handle SQL escaping
4. **Least Privilege**: Use database accounts with minimal required permissions

**Example**:
Bad:
\`\`\`javascript
const query = "SELECT * FROM users WHERE id = " + userId;
\`\`\`

Good:
\`\`\`javascript
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-89: SQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/89.html'
      },
      {
        title: 'OWASP SQL Injection Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '89'
  },
  xssVulnerability: {
    recommendation: `
**Cross-Site Scripting (XSS) Vulnerability**

**Why it Matters**: XSS allows attackers to inject malicious scripts that can steal user data, hijack sessions, or deface websites.

**What to Do**:
1. **Use Content Security Policy (CSP)**: Implement strict CSP headers
2. **Escape Output**: Always escape dynamic content before rendering
3. **Use Safe APIs**: Prefer innerHTML alternatives like textContent
4. **Input Validation**: Validate all user inputs

**Example**:
Bad:
\`\`\`javascript
element.innerHTML = userInput;
\`\`\`

Good:
\`\`\`javascript
element.textContent = userInput;
// Or if HTML is needed:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-79: Cross-site Scripting',
        url: 'https://cwe.mitre.org/data/definitions/79.html'
      },
      {
        title: 'OWASP XSS Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '79'
  },
  noSqlInjection: {
    recommendation: `
**NoSQL Injection Vulnerability**

**Why it Matters**: NoSQL injection can allow attackers to bypass authentication, access or modify unauthorized data, or cause denial of service.

**What to Do**:
1. **Use Proper Data Types**: Convert string inputs to proper types before queries
2. **Input Validation**: Validate each field individually
3. **Avoid \$where Operators**: Don't use \$where with user input
4. **Use Query Builders**: Prefer ODM/ORM query builders over raw queries

**Example**:
Bad:
\`\`\`javascript
db.users.find({ $where: "this.password === '" + userInput + "'" });
\`\`\`

Good:
\`\`\`javascript
db.users.find({ password: hash(userInput) });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-943: NoSQL Injection',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      },
      {
        title: 'OWASP NoSQL Injection',
        url: 'https://owasp.org/www-community/vulnerabilities/NoSQL_Injection'
      }
    ],
    cwe: '943'
  },
  weakCrypto: {
    recommendation: `
**Weak Cryptography Usage**

**Why it Matters**: Weak cryptographic functions can be easily broken, exposing sensitive data.

**What to Do**:
1. **Use Strong Algorithms**: Prefer SHA-256/SHA-512 over MD5/SHA1
2. **Keep Updated**: Use latest versions of crypto libraries
3. **Use Proper Key Lengths**: Follow NIST guidelines for key sizes
4. **Implement Salt**: Always salt password hashes

**Example**:
Bad:
\`\`\`javascript
const hash = crypto.createHash('md5');
\`\`\`

Good:
\`\`\`javascript
const hash = crypto.createHash('sha256');
// For passwords:
const hash = await bcrypt.hash(password, 12);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-326: Inadequate Encryption Strength',
        url: 'https://cwe.mitre.org/data/definitions/326.html'
      },
      {
        title: 'NIST Cryptographic Standards',
        url: 'https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines'
      }
    ],
    cwe: '326'
  },
  bufferIssue: {
    recommendation: `
**Unsafe Buffer Usage**

**Why it Matters**: Unsafe buffer operations can lead to buffer overflows and memory corruption.

**What to Do**:
1. **Use Safe Alternatives**: Prefer Buffer.alloc() over new Buffer()
2. **Check Bounds**: Validate buffer sizes and indices
3. **Update Node.js**: Use latest versions with security fixes
4. **Input Validation**: Validate all buffer-related inputs

**Example**:
Bad:
\`\`\`javascript
const buf = new Buffer(1024);
const unsafeBuf = Buffer.allocUnsafe(1024);
\`\`\`

Good:
\`\`\`javascript
const buf = Buffer.alloc(1024);
const buf2 = Buffer.from(data);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-119: Buffer Overflow',
        url: 'https://cwe.mitre.org/data/definitions/119.html'
      },
      {
        title: 'Node.js Buffer API',
        url: 'https://nodejs.org/api/buffer.html#buffer_buffer'
      }
    ],
    cwe: '119'
  },
  pathTraversal: {
    recommendation: `
**Path Traversal Vulnerability**

**Why it Matters**: Path traversal can allow attackers to access files outside intended directories.

**What to Do**:
1. **Normalize Paths**: Use path.normalize() to resolve paths
2. **Validate Paths**: Check if final path is within allowed directory
3. **Use path.join()**: Safely combine path segments
4. **Whitelist Extensions**: Only allow specific file types

**Example**:
Bad:
\`\`\`javascript
const filePath = "../" + userInput;
\`\`\`

Good:
\`\`\`javascript
const path = require('path');
const safePath = path.join(allowedDir, fileName);
if (!safePath.startsWith(allowedDir)) {
  throw new Error('Invalid path');
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-23: Path Traversal',
        url: 'https://cwe.mitre.org/data/definitions/23.html'
      },
      {
        title: 'OWASP Path Traversal',
        url: 'https://owasp.org/www-community/attacks/Path_Traversal'
      }
    ],
    cwe: '23'
  },
  openRedirect: {
    recommendation: `
**Open Redirect Vulnerability**

**Why it Matters**: Open redirects can be used in phishing attacks to make malicious URLs appear legitimate.

**What to Do**:
1. **Whitelist URLs**: Only allow redirects to known, safe domains
2. **Validate URLs**: Check URL format and destination
3. **Use Relative Paths**: Prefer relative to absolute redirects
4. **Implement Warnings**: Alert users about external redirects

**Example**:
Bad:
\`\`\`javascript
res.redirect(req.query.returnUrl);
\`\`\`

Good:
\`\`\`javascript
const allowedDomains = ['example.com', 'api.example.com'];
const url = new URL(req.query.returnUrl);
if (allowedDomains.includes(url.hostname)) {
  res.redirect(req.query.returnUrl);
} else {
  res.redirect('/');
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-601: URL Redirection to Untrusted Site',
        url: 'https://cwe.mitre.org/data/definitions/601.html'
      },
      {
        title: 'OWASP Unvalidated Redirects',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
      }
    ],
    cwe: '601'
  },
  ssrfVulnerability: {
    recommendation: `
**Server-Side Request Forgery (SSRF)**

**Why it Matters**: SSRF can allow attackers to make requests from your server to internal services or external targets.

**What to Do**:
1. **Whitelist Domains**: Only allow requests to approved domains
2. **Validate URLs**: Check URL format and destination
3. **Block Internal IPs**: Prevent requests to internal/private IPs
4. **Use Timeouts**: Set request timeouts to prevent DOS

**Example**:
Bad:
\`\`\`javascript
axios.get(userInput);
\`\`\`

Good:
\`\`\`javascript
const url = new URL(userInput);
if (isAllowedDomain(url.hostname)) {
  await axios.get(url.toString(), { timeout: 5000 });
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-918: Server-Side Request Forgery',
        url: 'https://cwe.mitre.org/data/definitions/918.html'
      },
      {
        title: 'OWASP SSRF Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
      }
    ],
    cwe: '918'
  },
  sessionFixation: {
    recommendation: `
**Why it Matters**: Session fixation lets attackers set or reuse a session ID.

**What to Do**:
1. **Regenerate Session** on login.
2. **Avoid session IDs in URLs**, use secure cookies instead.

**Example**:
Instead of:
\`\`\`javascript
req.session.id = req.query.sessionId;
\`\`\`
Do:
\`\`\`javascript
req.session.regenerate(() => { ... });
\`\`\`
    `,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html'
      }
    ],
    cwe: '384'
  },
  insecureAPISetup: {
    recommendation: `
**Why it Matters**: Insecure API setup without proper authentication middleware can expose your endpoints to unauthorized access and potential attacks.

**What to Do**:
1. **Implement Authentication Middleware**: Ensure that all API routes are protected with robust authentication mechanisms.
2. **Use Role-Based Access Control (RBAC)**: Define and enforce user roles and permissions.
3. **Validate API Inputs**: Sanitize and validate all incoming data to prevent injection attacks.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', apiHandler);
\`\`\`
Do:
\`\`\`javascript
app.use('/api', authenticateUser, apiHandler);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-921: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/921.html'
      },
      {
        title: 'OWASP Authentication Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
      }
    ],
    cwe: '921'
  },
  jwtInURL: {
    recommendation: `
**Why it Matters**: JWT tokens in URLs can be exposed through browser history, logs, or referer headers, leading to token theft and unauthorized access.

**What to Do**:
1. **Transmit JWTs via Headers**: Use the \`Authorization\` header to send JWTs securely.
2. **Avoid Including Tokens in URLs**: Refrain from appending tokens as query parameters.
3. **Implement Secure Storage**: Store tokens in secure, HTTP-only cookies or secure storage mechanisms.

**Example**:
Instead of:
\`\`\`javascript
axios.get(\`https://api.example.com/data?jwt=\${token}\`);
\`\`\`
Do:
\`\`\`javascript
axios.get('https://api.example.com/data', {
  headers: { Authorization: \`Bearer \${token}\` }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-922: Link Following Without Verification of Destination',
        url: 'https://cwe.mitre.org/data/definitions/922.html'
      },
      {
        title: 'OWASP JWT Security Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html'
      }
    ],
    cwe: '923'
  },
  tokenInURL: {
    recommendation: `
**Why it Matters**: Authentication tokens in URLs can be intercepted or exposed through logs, browser history, or referer headers, leading to unauthorized access.

**What to Do**:
1. **Use Secure Headers**: Transmit tokens via the \`Authorization\` header.
2. **Avoid URL Parameters for Sensitive Data**: Do not include tokens or sensitive information in URLs.
3. **Implement HTTPS**: Ensure all communications are encrypted to protect token transmission.

**Example**:
Instead of:
\`\`\`javascript
fetch(\`http://example.com/api?token=\${authToken}\`);
\`\`\`
Do:
\`\`\`javascript
fetch('https://example.com/api', {
  headers: { Authorization: \`Bearer \${authToken}\` }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-922: Link Following Without Verification of Destination',
        url: 'https://cwe.mitre.org/data/definitions/922.html'
      },
      {
        title: 'OWASP JWT Security Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html'
      }
    ],
    cwe: '923'
  },
  badRateLimit: {
    recommendation: `
**Why it Matters**: Weak rate limiting configurations can be exploited for brute-force attacks, denial-of-service (DoS), or abuse of API endpoints.

**What to Do**:
1. **Implement Strong Rate Limiting**: Define sensible limits on the number of requests per user/IP.
2. **Use Distributed Rate Limiting**: Ensure rate limits are enforced across multiple servers or instances.
3. **Provide Feedback**: Inform users when rate limits are exceeded without revealing sensitive information.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
\`\`\`
Do:
\`\`\`javascript
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later."
}));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-924: Improper Enforcement of Business Rules',
        url: 'https://cwe.mitre.org/data/definitions/924.html'
      },
      {
        title: 'OWASP Rate Limiting Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html'
      }
    ],
    cwe: '924'
  },
  missingCORS: {
    recommendation: `
**Why it Matters**: Improper or missing Cross-Origin Resource Sharing (CORS) configurations can allow unauthorized domains to interact with your APIs, leading to data leaks or unauthorized actions.

**What to Do**:
1. **Configure CORS Properly**: Define allowed origins, methods, and headers explicitly.
2. **Restrict Access**: Limit CORS to trusted domains only.
3. **Use Credentials Wisely**: Ensure that credentials are only sent to trusted origins.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', cors());
\`\`\`
Do:
\`\`\`javascript
app.use('/api', cors({
  origin: ['https://trusted-domain.com'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-925: Use of Existing, Secure Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'OWASP CORS Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html'
      }
    ],
    cwe: '925'
  },
  insecureMiddleware: {
    recommendation: `
**Why it Matters**: Insecure middleware setups can inadvertently expose sensitive endpoints or allow unauthorized access, undermining the security of your APIs.

**What to Do**:
1. **Ensure Authentication Middleware is Properly Placed**: Protect sensitive routes by placing authentication middleware before route handlers.
2. **Limit Middleware Scope**: Apply middleware only to necessary routes to minimize exposure.
3. **Regularly Review Middleware Configurations**: Audit middleware settings to ensure they adhere to security best practices.

**Example**:
Instead of:
\`\`\`javascript
app.use('/api', someMiddleware, apiHandler);
\`\`\`
Do:
\`\`\`javascript
app.use('/api', authenticateUser, someMiddleware, apiHandler);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-926: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/926.html'
      },
      {
        title: 'OWASP Secure Headers Project',
        url: 'https://owasp.org/www-project-secure-headers/'
      }
    ],
    cwe: '926'
  },
  vulnerableDependency: {
    recommendation: `
**Why it Matters**: Vulnerable dependencies can be exploited to compromise your application, leading to data breaches or unauthorized access.

**What to Do**:
1. **Update Dependencies**: Regularly update dependencies to their latest secure versions.
2. **Use Automated Tools**: Integrate tools like \`npm audit\`, \`Snyk\`, or \`Dependabot\` to monitor and remediate vulnerabilities.
3. **Limit Dependencies**: Only include necessary dependencies to reduce the attack surface.

**Example**:
Instead of:
\`\`\`json
"dependencies": {
  "lodash": "^4.17.15"
}
\`\`\`
Do:
\`\`\`json
"dependencies": {
  "lodash": "^4.17.21"
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-925: Use of Existing, Secure Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/925.html'
      },
      {
        title: 'OWASP Dependency-Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      }
    ],
    cwe: '925'
  },
  outdatedDependency: {
    recommendation: `
**Why it Matters**: Outdated dependencies may lack the latest security patches, exposing your application to known vulnerabilities.

**What to Do**:
1. **Regularly Review Dependencies**: Periodically check and update dependencies to their latest versions.
2. **Automate Updates**: Use tools like \`npm outdated\`, \`Dependabot\`, or \`Renovate\` to automate dependency updates.
3. **Test After Updates**: Ensure that updates do not break application functionality by implementing comprehensive testing.

**Example**:
Instead of:
\`\`\`json
"dependencies": {
  "express": "^4.16.0"
}
\`\`\`
Do:
\`\`\`json
"dependencies": {
  "express": "^4.18.2"
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-926: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/926.html'
      },
      {
        title: 'OWASP Dependency-Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      }
    ],
    cwe: '926'
  },
  memoryLeak: {
    description: `
**Memory Leak Vulnerability**

Memory leaks can occur when timers and intervals are not properly cleared, especially in long-running applications or components that are frequently mounted and unmounted.

**Why it Matters**: Memory leaks can degrade application performance over time and eventually lead to crashes or out-of-memory errors.

**What to Do**:
1. **Clear Timers**: Always clear setInterval and setTimeout when they are no longer needed
2. **Use Cleanup Functions**: In React components, use useEffect cleanup function
3. **Monitor Memory Usage**: Implement memory monitoring in production
4. **Proper Resource Management**: Ensure all resources are properly released

**Example**:
Bad:
\`\`\`javascript
setInterval(() => {
  // Some operation
}, 1000);
\`\`\`

Good:
\`\`\`javascript
const timer = setInterval(() => {
  // Some operation
}, 1000);

// Clear when done
clearInterval(timer);

// In React:
useEffect(() => {
  const timer = setInterval(() => {
    // Some operation
  }, 1000);
  return () => clearInterval(timer);
}, []);
\`\`\`
    `,
    references: [
      {
        title: 'Memory Management Best Practices',
        url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Memory_Management'
      },
      {
        title: 'CWE-401: Memory Leak',
        url: 'https://cwe.mitre.org/data/definitions/401.html'
      }
    ]
  },
  insecureDirectObjectRef: {
    description: `
**Insecure Direct Object References (IDOR)**

IDOR vulnerabilities occur when an application uses user-supplied input to access objects directly without proper access control checks.

**Why it Matters**: Attackers can bypass authorization and access or modify data belonging to other users.

**What to Do**:
1. **Implement Access Controls**: Always verify user has permission to access requested resource
2. **Use Indirect References**: Map internal object references to user-specific tokens
3. **Input Validation**: Validate all user input before using in database queries
4. **Proper Authorization**: Check user permissions at both controller and service layers

**Example**:
Bad:
\`\`\`javascript
app.get('/api/document/:id', (req, res) => {
  return db.getDocument(req.params.id);
});
\`\`\`

Good:
\`\`\`javascript
app.get('/api/document/:id', async (req, res) => {
  const userId = req.user.id;
  const doc = await db.getDocument(req.params.id);
  if (doc.ownerId !== userId) {
    return res.status(403).json({ error: 'Access denied' });
  }
  return res.json(doc);
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-639: Authorization Bypass Through User-Controlled Key',
        url: 'https://cwe.mitre.org/data/definitions/639.html'
      },
      {
        title: 'OWASP IDOR Prevention',
        url: 'https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference'
      }
    ]
  },
  improperAuthorizationChecks: {
    description: `
**Improper Authorization Checks**

Improper authorization checks can lead to unauthorized access to resources or functionality.

**Why it Matters**: Without proper authorization checks, users can access data or perform actions they shouldn't be allowed to.

**What to Do**:
1. **Implement RBAC**: Use Role-Based Access Control
2. **Check at Multiple Levels**: Verify authorization at API and service layers
3. **Use Middleware**: Implement authorization middleware
4. **Audit Trails**: Log all access attempts

**Example**:
Bad:
\`\`\`javascript
if (req.user) {  // Only checks authentication
  return handleAdminAction();
}
\`\`\`

Good:
\`\`\`javascript
if (!req.user.hasRole('admin')) {
  return res.status(403).json({ 
    error: 'Requires admin privileges' 
  });
}
await auditLog.log('admin_action', req.user.id);
return handleAdminAction();
\`\`\`
    `,
    references: [
      {
        title: 'CWE-285: Improper Authorization',
        url: 'https://cwe.mitre.org/data/definitions/285.html'
      },
      {
        title: 'OWASP Authorization Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
      }
    ]
  },
  unsafeDeserialization: {
    description: `
**Unsafe Deserialization of User Data**

**Why it Matters**: Untrusted deserialization can lead to remote code execution, denial of service, or injection attacks.

**What to Do**:
1. **Use Safe Alternatives**: Prefer JSON.parse with schema validation
2. **Input Validation**: Validate data before deserialization
3. **Schema Validation**: Use libraries like Joi or Yup
4. **Whitelist Properties**: Only deserialize expected properties

**Example**:
Bad:
\`\`\`javascript
const data = unserialize(userInput);
const obj = JSON.parse(userInput);
\`\`\`

Good:
\`\`\`javascript
import { object, string } from 'yup';

const schema = object({
  name: string().required(),
  email: string().email().required()
});

try {
  const data = await schema.validate(JSON.parse(userInput));
} catch (err) {
  // Handle validation error
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-502: Deserialization of Untrusted Data',
        url: 'https://cwe.mitre.org/data/definitions/502.html'
      },
      {
        title: 'OWASP Deserialization',
        url: 'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data'
      }
    ]
  },
  sessionFixation: {
    description: `
**Session Fixation Vulnerability**

**Why it Matters**: Session fixation allows attackers to hijack user sessions by forcing them to use a known session ID.

**What to Do**:
1. **Regenerate Session**: Create new session ID after authentication
2. **Validate Session**: Verify session data matches user
3. **Session Timeout**: Implement proper session expiration
4. **Secure Cookies**: Use secure, httpOnly cookies

**Example**:
Bad:
\`\`\`javascript
app.post('/login', (req, res) => {
  if (validCredentials(req.body)) {
    req.session.userId = user.id;  // Reusing existing session
  }
});
\`\`\`

Good:
\`\`\`javascript
app.post('/login', (req, res) => {
  if (validCredentials(req.body)) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).end();
      req.session.userId = user.id;
      req.session.created = Date.now();
    });
  }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-384: Session Fixation',
        url: 'https://cwe.mitre.org/data/definitions/384.html'
      },
      {
        title: 'OWASP Session Fixation',
        url: 'https://owasp.org/www-community/attacks/Session_fixation'
      }
    ]
  },
  insecureCookie: {
    description: `
**Insecure Cookie Configuration**

**Why it Matters**: Cookies without proper security flags can be stolen or manipulated by attackers.

**What to Do**:
1. **Set Secure Flag**: Ensure cookies only sent over HTTPS
2. **Set HttpOnly**: Prevent JavaScript access to cookies
3. **Set SameSite**: Protect against CSRF attacks
4. **Use Secure Defaults**: Configure framework defaults properly

**Example**:
Bad:
\`\`\`javascript
res.cookie('sessionId', 'abc123');
res.cookie('authToken', token, { httpOnly: false });
\`\`\`

Good:
\`\`\`javascript
res.cookie('sessionId', 'abc123', {
  secure: true,
  httpOnly: true,
  sameSite: 'strict'
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-614: Sensitive Cookie Without Secure Flag',
        url: 'https://cwe.mitre.org/data/definitions/614.html'
      },
      {
        title: 'OWASP Session Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
      }
    ]
  },
  sensitiveDataExposure: {
    description: `
**Sensitive Data Exposure**

**Why it Matters**: Exposing sensitive data in logs or error messages can lead to data breaches.

**What to Do**:
1. **Sanitize Logs**: Remove sensitive data before logging
2. **Use Log Levels**: Control verbosity of logging
3. **Mask Data**: Hide sensitive portions of data
4. **Audit Logs**: Regular review of logging practices

**Example**:
Bad:
\`\`\`javascript
console.log('User data:', { password, ssn, creditCard });
logger.info(\`API Key used: \${apiKey}\`);
\`\`\`

Good:
\`\`\`javascript
const sanitize = obj => {
  const masked = { ...obj };
  delete masked.password;
  delete masked.ssn;
  return masked;
};
console.log('User data:', sanitize(userData));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-200: Exposure of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/200.html'
      },
      {
        title: 'OWASP Sensitive Data Exposure',
        url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
      }
    ]
  },
  clearTextTransmission: {
    description: `
**Cleartext Data Transmission**

**Why it Matters**: Data sent over HTTP can be intercepted and read by attackers.

**What to Do**:
1. **Use HTTPS**: Always use HTTPS for data transmission
2. **HSTS**: Implement HTTP Strict Transport Security
3. **Redirect HTTP**: Automatically redirect HTTP to HTTPS
4. **Valid Certificates**: Maintain valid SSL/TLS certificates

**Example**:
Bad:
\`\`\`javascript
fetch('http://api.example.com/data');
axios.get('http://payment.example.com');
\`\`\`

Good:
\`\`\`javascript
fetch('https://api.example.com/data');
app.use(helmet.hsts({ maxAge: 31536000 }));
\`\`\`
    `,
    references: [
      {
        title: 'CWE-319: Cleartext Transmission',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      },
      {
        title: 'OWASP Transport Layer Protection',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'
      }
    ]
  },
  improperInputValidation: {
    description: `
**Improper Input Validation**

**Why it Matters**: Lack of input validation can lead to injection attacks, buffer overflows, and other vulnerabilities.

**What to Do**:
1. **Validate Input**: Check type, length, format, and range
2. **Use Schema Validation**: Implement strong validation libraries
3. **Sanitize Output**: Encode/escape output appropriately
4. **Whitelist Validation**: Prefer whitelist over blacklist

**Example**:
Bad:
\`\`\`javascript
app.get('/api/user/:id', (req, res) => {
  db.findUser(req.params.id);  // No validation
});
\`\`\`

Good:
\`\`\`javascript
const { body, param, validationResult } = require('express-validator');

app.get('/api/user/:id', [
  param('id').isInt().toInt(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
], async (req, res) => {
  const user = await db.findUser(req.params.id);
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-20: Improper Input Validation',
        url: 'https://cwe.mitre.org/data/definitions/20.html'
      },
      {
        title: 'OWASP Input Validation Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
      }
    ]
  },
  vulnerableDependency: {
    description: `
**Use of Vulnerable Dependencies**

**Why it Matters**: Using packages with known vulnerabilities exposes your application to attacks.

**What to Do**:
1. **Regular Audits**: Use npm audit or similar tools
2. **Version Pinning**: Pin dependency versions
3. **Security Updates**: Keep dependencies updated
4. **Dependency Scanning**: Implement automated scanning

**Example**:
Bad:
\`\`\`javascript
{
  "dependencies": {
    "outdated-package": "*",
    "vulnerable-library": "1.0.0"
  }
}
\`\`\`

Good:
\`\`\`javascript
// package.json
{
  "scripts": {
    "audit": "npm audit && snyk test",
    "outdated": "npm outdated"
  },
  "dependencies": {
    "secure-package": "^2.1.0"
  }
}
\`\`\`
    `,
    references: [
      {
        title: 'CWE-937: Using Components with Known Vulnerabilities',
        url: 'https://cwe.mitre.org/data/definitions/937.html'
      },
      {
        title: 'OWASP Dependency Check',
        url: 'https://owasp.org/www-project-dependency-check/'
      }
    ]
  },
  insecureAPIStructure: {
    description: `
**Insecure API Parameter Structure**

**Why it Matters**: Poor API URL structure can expose internal IDs, enable enumeration attacks, or allow parameter tampering.

**What to Do**:
1. **Use Opaque IDs**: Replace sequential IDs with UUIDs or hashed values
2. **Validate Parameters**: Implement strict parameter validation
3. **Proper Nesting**: Use proper resource nesting in URLs
4. **Query Parameters**: Sensitive filters should use POST body instead of URL

**Example**:
Bad:
\`\`\`javascript
// Sequential IDs expose database structure
app.get('/api/users/:id/secrets');
// Multiple parameters enable enumeration
app.get('/api/org/:orgId/user/:userId');
// Sensitive data in query
app.get('/api/search?q=ssn:123-45-6789');
\`\`\`

Good:
\`\`\`javascript
// Opaque IDs
app.get('/api/users/:uuid/data');
// Proper resource nesting
app.get('/api/users/:uuid');
// Sensitive queries in body
app.post('/api/search', validateBody, (req, res) => {
  // Validate and sanitize req.body.query
});
\`\`\`
    `,
    references: [
      {
        title: 'OWASP API Security Top 10',
        url: 'https://owasp.org/www-project-api-security/'
      },
      {
        title: 'CWE-20: Improper Input Validation',
        url: 'https://cwe.mitre.org/data/definitions/20.html'
      }
    ]
  },
  massAssignment: {
    description: `
**Mass Assignment Vulnerability**

**Why it Matters**: Directly assigning request body to models can allow attackers to modify unauthorized fields.

**What to Do**:
1. **Whitelist Properties**: Explicitly list allowed fields
2. **Separate DTOs**: Use separate objects for API input
3. **Input Validation**: Validate each field individually
4. **Remove Sensitive Fields**: Strip out sensitive fields before processing

**Example**:
Bad:
\`\`\`javascript
// Dangerous mass assignment
app.post('/api/users', (req, res) => {
  const user = new User(req.body);
  // Attacker can set isAdmin=true!
});

// Spread operator danger
app.put('/api/users/:id', (req, res) => {
  const updates = { ...req.body };
  // Attacker can modify any field!
});
\`\`\`

Good:
\`\`\`javascript
app.post('/api/users', (req, res) => {
  // Explicit field selection
  const { name, email } = req.body;
  const user = new User({ name, email });
});

app.put('/api/users/:id', (req, res) => {
  // Whitelist allowed fields
  const allowedUpdates = ['name', 'email'];
  const updates = {};
  for (const field of allowedUpdates) {
    if (field in req.body) {
      updates[field] = req.body[field];
    }
  }
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-915: Improperly Controlled Modification of Object',
        url: 'https://cwe.mitre.org/data/definitions/915.html'
      }
    ]
  },
  inconsistentAuth: {
    description: `
**Inconsistent API Authentication**

**Why it Matters**: Missing authentication on some endpoints can create security holes in your API surface.

**What to Do**:
1. **Consistent Middleware**: Use authentication middleware consistently
2. **Route Groups**: Group routes by authentication requirements
3. **Explicit Public Routes**: Clearly document and review public endpoints
4. **Auth Hierarchy**: Implement proper auth inheritance in route structures

**Example**:
Bad:
\`\`\`javascript
// Inconsistent auth
app.get('/api/users', auth, getUsers);
app.get('/api/users/:id', getUser);       // Missing auth!
app.put('/api/users/:id', auth, updateUser);

// Mixed auth in same resource
router.get('/api/docs', auth, getDocs);
router.get('/api/docs/public', getPublicDocs);  // Confusing structure
\`\`\`

Good:
\`\`\`javascript
// Consistent auth with explicit public routes
const apiRouter = express.Router();
apiRouter.use(auth);  // All routes require auth by default

// Protected routes
apiRouter.get('/users', getUsers);
apiRouter.get('/users/:id', getUser);
apiRouter.put('/users/:id', updateUser);

// Explicit public routes in separate router
const publicRouter = express.Router();
publicRouter.get('/docs/public', getPublicDocs);

app.use('/api', apiRouter);
app.use('/public', publicRouter);
\`\`\`
    `,
    references: [
      {
        title: 'CWE-306: Missing Authentication for Critical Function',
        url: 'https://cwe.mitre.org/data/definitions/306.html'
      }
    ]
  },
  verbTampering: {
    description: `
**HTTP Verb Tampering Vulnerability**

**Why it Matters**: Improper handling of HTTP methods can allow attackers to bypass intended access controls.

**What to Do**:
1. **Explicit Methods**: Specify exact HTTP methods
2. **Proper Status Codes**: Return 405 for invalid methods
3. **Avoid app.all()**: Don't use catch-all method handlers
4. **Secure Method Override**: Disable or strictly control method override

**Example**:
Bad:
\`\`\`javascript
// Dangerous catch-all
app.all('/api/users/:id', (req, res) => {
  // Same handler for all methods!
});

// Implicit method handling
app.use('/api/posts/:id', (req, res) => {
  // No method checking
});
\`\`\`

Good:
\`\`\`javascript
// Explicit method handlers
app.get('/api/users/:id', getUser);
app.put('/api/users/:id', updateUser);
app.delete('/api/users/:id', deleteUser);

// Handle invalid methods
app.use('/api/users/:id', (req, res) => {
  res.status(405).json({ error: 'Method not allowed' });
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-434: Unrestricted Upload of File with Dangerous Type',
        url: 'https://cwe.mitre.org/data/definitions/434.html'
      }
    ]
  },
  sensitiveData: {
    description: `
**Sensitive Data Exposure**

**Why it Matters**: Exposing sensitive data in code, configuration, or logs can lead to data breaches and compromised systems.

**What to Do**:
1. **Environment Variables**: Store sensitive data in environment variables
2. **Secret Management**: Use a secure secret management system
3. **Data Encryption**: Encrypt sensitive data at rest
4. **Access Control**: Implement proper access controls

**Example**:
Bad:
\`\`\`javascript
// Hardcoded secrets
const apiKey = "1234567890";
const password = "secretpass";
const privateKey = readFileSync('private.key');

// Sensitive data in code
const user = {
  ssn: "123-45-6789",
  creditCard: "4111-1111-1111-1111"
};
\`\`\`

Good:
\`\`\`javascript
// Use environment variables
const apiKey = process.env.API_KEY;
const password = process.env.DB_PASSWORD;

// Encrypt sensitive data
const encrypted = encrypt(userData.ssn);
db.users.save({ ssn_encrypted: encrypted });

// Use secret management
const secret = await secretManager.getSecret('api-key');
\`\`\`
    `,
    references: [
      {
        title: 'CWE-200: Exposure of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/200.html'
      },
      {
        title: 'OWASP Top 10: Sensitive Data Exposure',
        url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
      }
    ]
  },
  insecureTransmission: {
    description: `
**Insecure Data Transmission**

**Why it Matters**: Data transmitted over insecure protocols can be intercepted, modified, or stolen.

**What to Do**:
1. **Use HTTPS**: Always use HTTPS for data transmission
2. **Secure WebSocket**: Use WSS instead of WS
3. **Certificate Validation**: Validate SSL/TLS certificates
4. **Internal Traffic**: Encrypt internal service communication

**Example**:
Bad:
\`\`\`javascript
// Insecure HTTP
fetch('http://api.example.com/data');
new WebSocket('ws://example.com');

// Internal services
axios.get('http://internal-service/');
\`\`\`

Good:
\`\`\`javascript
// Secure HTTPS
fetch('https://api.example.com/data');
new WebSocket('wss://example.com');

// Internal with TLS
axios.get('https://internal-service/', {
  httpsAgent: new https.Agent({
    rejectUnauthorized: true
  })
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-319: Cleartext Transmission of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      },
      {
        title: 'OWASP Transport Layer Protection',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'
      }
    ]
  },
  insecureTransport: {
    description: 'Use of insecure transport protocols',
    severity: 'HIGH',
    mitigation: `
**What to Do**:
1. **Always Use HTTPS**: Use HTTPS for all external communications
2. **Verify Certificates**: Enable certificate validation
3. **Internal Services**: Use TLS even for internal services
4. **WebSocket Security**: Use WSS instead of WS

**Example**:
Bad:
\`\`\`javascript
// Insecure HTTP
fetch('http://api.example.com/data');
new WebSocket('ws://example.com');

// Internal services
axios.get('http://internal-service/');
\`\`\`

Good:
\`\`\`javascript
// Secure HTTPS
fetch('https://api.example.com/data');
new WebSocket('wss://example.com');

// Internal with TLS
axios.get('https://internal-service/', {
  httpsAgent: new https.Agent({
    rejectUnauthorized: true
  })
});
\`\`\`
    `,
    references: [
      {
        title: 'CWE-319: Cleartext Transmission of Sensitive Information',
        url: 'https://cwe.mitre.org/data/definitions/319.html'
      },
      {
        title: 'OWASP Transport Layer Protection',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'
      }
    ]
  }
};

// Main scanning function
export async function scanFile(content, options = {}) {
  const startTime = Date.now();
  const results = {
    matches: [],
    errors: [],
    performance: {
      duration: 0
    }
  };

  // Input validation
  if (!content || typeof content !== 'string') {
    results.errors.push('Invalid input: content must be a string');
    return results;
  }

  // Pattern matching
  for (const [name, pattern] of Object.entries(patterns)) {
    try {
      if (testPattern(name, pattern.pattern, content)) {
        const line = findMatchingLine(content, pattern.pattern);
        results.matches.push({
          id: name,
          pattern: name,
          name: pattern.description,
          severity: pattern.severity,
          category: pattern.category,
          line,
          context: line ? extractContext(content, line) : '',
          recommendation: recommendations[name],
          references: pattern.references
        });
      }
    } catch (error) {
      results.errors.push(`Pattern ${name} error: ${error.message}`);
    }
  }

  // Sort by severity
  results.matches.sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity));
  
  // Set performance metrics
  results.performance.duration = Date.now() - startTime;

  return results;
}

// Simple scan interface
export function scan(content) {
  return scanFile(content);
}

// Export for testing
export const __testing = {
  validatePattern,
  testPattern,
  findMatchingLine,
  extractContext,
  severityOrder
};
