// Core vulnerability patterns that are always enabled
export const corePatterns = {
    evalUsage: {
        pattern: /(?<!//\s*)eval\s*\(/,
        severity: 'CRITICAL',
        description: 'Use of eval() is dangerous and can lead to code injection'
    },
    dynamicImports: {
        pattern: /(?<!//\s*)import\s*\(\s*(?!['"`][^'"`]+['"`])[^)]*\)/,
        severity: 'HIGH',
        description: 'Dynamic imports without validation can lead to code execution vulnerabilities'
    },
    bufferOverflow: {
        pattern: /(?<!//\s*)Buffer\.allocUnsafe\s*\(/,
        severity: 'MEDIUM',
        description: 'Use of Buffer.allocUnsafe() should be replaced with Buffer.alloc()'
    },
    consoleUsage: {
        pattern: /console\.(log|debug|info)\s*\(/,
        severity: 'LOW',
        description: 'Console statements should be removed in production'
    },
    hardcodedSecrets: {
        pattern: /(password|secret|key|token|api[_-]?key)\s*=\s*['"`][^'"`]{8,}['"`]/i,
        severity: 'HIGH',
        description: 'Potential hardcoded secret detected'
    },
    unsafeRegex: {
        pattern: /new RegExp\([^)]+\)/,
        severity: 'MEDIUM',
        description: 'Dynamic RegExp construction could lead to ReDoS attacks'
    },
    unsafeJsonParse: {
        pattern: /JSON\.parse\s*\([^)]+\)(?!\s*\.(catch|then)|\s*catch\s*{)/,
        severity: 'LOW',
        description: 'Unhandled JSON.parse can throw on invalid input'
    },
    debuggerStatement: {
        pattern: /debugger;/,
        severity: 'LOW',
        description: 'Debugger statement should be removed in production'
    }
};

// Enhanced vulnerability patterns that can be toggled
export const enhancedPatterns = {
    sqlInjection: {
        pattern: /(?<!//\s*)(executeQuery|query)\s*\(\s*[`'"].*?\${.*?}.*?[`'"]\s*\)/,
        severity: 'CRITICAL',
        description: 'Potential SQL injection vulnerability detected through template literal usage in queries'
    },
    xss: {
        pattern: /(?<!//\s*)(innerHTML|outerHTML)\s*=|document\.write\(|(?<!\.escape\().*?\${.*?}.*?(?=\`)/,
        severity: 'CRITICAL',
        description: 'Potential XSS vulnerability through unsafe DOM manipulation or unescaped template literals'
    },
    insecurePasswords: {
        pattern: /(crypto\.createHash\(['"]md5['"]\)|crypto\.createHash\(['"]sha1['"]\))/,
        severity: 'HIGH',
        description: 'Use of weak hashing algorithms (MD5/SHA1) for passwords'
    },
    sensitiveDataExposure: {
        pattern: /(?<!//\s*)(console\.(log|debug|info|warn|error)|alert)\s*\([^)]*(?:password|secret|key|token|credentials)[^)]*\)/i,
        severity: 'HIGH',
        description: 'Potential exposure of sensitive data through logging or alerts'
    },
    insecureRandomness: {
        pattern: /Math\.random\(\)/,
        severity: 'MEDIUM',
        description: 'Use of Math.random() for security-sensitive operations. Use crypto.getRandomValues() instead'
    },
    noAuthenticationCheck: {
        pattern: /(?<!//\s*)(?:delete|update|remove|drop)\s*(?:user|account|data|record).*?(?<!check.*?)(?<!verify.*?)(?<!authenticate.*?)(?<!authorize.*?)\(/i,
        severity: 'HIGH',
        description: 'Critical operation without apparent authentication check'
    },
    pathTraversal: {
        pattern: /(?<!//\s*)(fs\.read|fs\.write|fs\.append).*?\+\s*(?:req\.params|req\.query|req\.body)/,
        severity: 'CRITICAL',
        description: 'Potential path traversal vulnerability through unvalidated user input'
    },
    insecureDirectObjectRef: {
        pattern: /(?<!//\s*)(?:findById|getById|selectById).*?(?:req\.params|req\.query|req\.body)/,
        severity: 'HIGH',
        description: 'Potential Insecure Direct Object Reference (IDOR) through unvalidated user input'
    },
    noHttpsEnforcement: {
        pattern: /(?<!//\s*)http:\/\//,
        severity: 'MEDIUM',
        description: 'Use of non-HTTPS URLs detected'
    }
};

// Recommendation messages for each vulnerability type
export const recommendations = {
    // Core recommendations
    evalUsage: 'Replace eval() with safer alternatives like JSON.parse() or Function()',
    dynamicImports: 'Implement strict path validation for dynamic imports',
    bufferOverflow: 'Use Buffer.alloc() instead of Buffer.allocUnsafe()',
    consoleUsage: 'Remove console statements or use a logging library',
    hardcodedSecrets: 'Move secrets to environment variables or secure secret management',
    unsafeRegex: 'Use static regular expressions or validate dynamic patterns',
    unsafeJsonParse: 'Add try/catch blocks around JSON.parse calls',
    debuggerStatement: 'Remove debugger statements before deploying to production',
    
    // Enhanced recommendations
    sqlInjection: 'Use parameterized queries or an ORM to prevent SQL injection',
    xss: 'Use dedicated HTML sanitization libraries and avoid direct DOM manipulation with user input',
    insecurePasswords: 'Use strong hashing algorithms like bcrypt, Argon2, or PBKDF2',
    sensitiveDataExposure: 'Remove debug logging of sensitive data and implement proper logging policies',
    insecureRandomness: 'Replace Math.random() with crypto.getRandomValues() for security operations',
    noAuthenticationCheck: 'Implement proper authentication checks before critical operations',
    pathTraversal: 'Implement strict input validation and use path normalization',
    insecureDirectObjectRef: 'Implement proper authorization checks and use indirect references',
    noHttpsEnforcement: 'Enforce HTTPS by redirecting HTTP to HTTPS and using secure cookies'
};