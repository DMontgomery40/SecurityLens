// Add category structure
export const patternCategories = {
    CRITICAL_EXECUTION: '94',  // Code injection/execution
    AUTHENTICATION: '287',     // Auth bypass/missing auth
    INJECTION: '74',          // Various injection types (SQL, Command, etc)
    CRYPTO_ISSUES: '310',     // Cryptographic/encryption issues
    MEMORY_BUFFER: '119',     // Buffer/memory issues
    DATA_PROTECTION: '200',    // Sensitive data exposure
    INPUT_VALIDATION: '20',   // Input validation issues
    ERROR_HANDLING: '389',    // Error handling & logging
    ACCESS_CONTROL: '264',    // Permission & privilege issues
    RESOURCE_MGMT: '399'      // Resource management & leaks
};

// Modify core patterns structure
export const corePatterns = {
    // CRITICAL EXECUTION VULNERABILITIES
    evalExecution: {
        pattern: /eval\s*\([^)]*\)|new\s+Function\s*\(/,
        description: 'Dangerous code execution via eval() or Function constructor',
        severity: 'CRITICAL',
        category: patternCategories.CRITICAL_EXECUTION,
        subcategory: '95'  // Eval injection
    },
    commandInjection: {
        pattern: /child_process\.exec\s*\(|\.exec\s*\(|\.spawn\s*\(/,
        description: 'Potential command injection vulnerability',
        severity: 'CRITICAL',
        category: patternCategories.CRITICAL_EXECUTION,
        subcategory: '77'  // Command injection
    },

    // AUTHENTICATION VULNERABILITIES
    missingAuth: {
        pattern: /authentication:\s*false|auth:\s*false|noAuth:\s*true|skipAuth/i,
        description: 'Authentication bypass or missing authentication',
        severity: 'CRITICAL',
        category: patternCategories.AUTHENTICATION,
        subcategory: '306'  // Missing authentication
    },
    hardcodedCreds: {
        pattern: /(password|secret|key|token|credential)s?\s*[:=]\s*['"`][^'"`]+['"`]/i,
        description: 'Hardcoded credentials detected',
        severity: 'CRITICAL',
        category: patternCategories.AUTHENTICATION,
        subcategory: '798'  // Use of hard-coded credentials
    },

    // INJECTION VULNERABILITIES
    sqlInjection: {
        pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
        description: 'Potential SQL injection vulnerability',
        severity: 'CRITICAL',
        category: patternCategories.INJECTION,
        subcategory: '89'  // SQL injection
    },
    xssVulnerability: {
        pattern: /innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|\$\(.*\)\.html\s*\(/,
        description: 'Cross-site scripting vulnerability',
        severity: 'HIGH',
        category: patternCategories.INJECTION,
        subcategory: '79'  // XSS
    },

    // MEMORY & BUFFER VULNERABILITIES
    bufferIssue: {
        pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(/,
        description: 'Unsafe buffer allocation',
        severity: 'HIGH',
        category: patternCategories.MEMORY_BUFFER,
        subcategory: '119'  // Buffer overflow
    },
    memoryLeak: {
        pattern: /(setInterval|setTimeout)\s*\([^,]+,[^)]+\)/,
        description: 'Potential memory leak in timer/interval',
        severity: 'MEDIUM',
        category: patternCategories.MEMORY_BUFFER,
        subcategory: '401'  // Memory leak
    },

    // DATA PROTECTION VULNERABILITIES
    sensitiveData: {
        pattern: /(password|token|secret|key|credential)s?\s*=\s*[^;]+/i,
        description: 'Sensitive data exposure',
        severity: 'HIGH',
        category: patternCategories.DATA_PROTECTION,
        subcategory: '200'  // Information exposure
    },
    insecureTransmission: {
        pattern: /https?:\/\/(?!localhost|127\.0\.0\.1)/,
        description: 'Potential insecure data transmission',
        severity: 'MEDIUM',
        category: patternCategories.DATA_PROTECTION,
        subcategory: '319'  // Cleartext transmission
    }
};

// Enhance recommendations with CWE references
export const recommendations = {
    evalExecution: {
        recommendation: 'Avoid using eval() or new Function(). Use safer alternatives like JSON.parse() for JSON data, or implement specific functionality without dynamic code execution.',
        references: [
            {
                title: 'CWE-95: Eval Injection',
                url: 'https://cwe.mitre.org/data/definitions/95.html',
                description: 'Comprehensive guide on eval injection vulnerabilities'
            }
        ],
        cwe: '95'
    },
    commandInjection: {
        recommendation: 'Use child_process.execFile() instead of exec(), and always sanitize user input. Implement proper input validation and use parameterized commands.',
        references: [
            {
                title: 'CWE-77: Command Injection',
                url: 'https://cwe.mitre.org/data/definitions/77.html',
                description: 'Details on preventing command injection attacks'
            }
        ],
        cwe: '77'
    },
    missingAuth: {
        recommendation: 'Implement proper authentication for all sensitive operations. Never disable authentication in production code.',
        references: [
            {
                title: 'CWE-306: Missing Authentication',
                url: 'https://cwe.mitre.org/data/definitions/306.html',
                description: 'Understanding missing authentication vulnerabilities'
            }
        ],
        cwe: '306'
    },
    hardcodedCreds: {
        recommendation: 'Never hardcode credentials in source code. Use environment variables or secure credential management systems.',
        references: [
            {
                title: 'CWE-798: Use of Hard-coded Credentials',
                url: 'https://cwe.mitre.org/data/definitions/798.html',
                description: 'Risks of hardcoded credentials'
            },
            {
                title: 'OWASP Secure Configuration Guide',
                url: 'https://owasp.org/www-project-secure-configuration-guide/',
                description: 'Best practices for credential management'
            }
        ],
        cwe: '798'
    },
    sqlInjection: {
        recommendation: 'Use parameterized queries or an ORM. Never concatenate user input directly into SQL queries.',
        references: [
            {
                title: 'CWE-89: SQL Injection',
                url: 'https://cwe.mitre.org/data/definitions/89.html',
                description: 'Understanding SQL injection vulnerabilities'
            },
            {
                title: 'OWASP SQL Injection Prevention',
                url: 'https://owasp.org/www-community/attacks/SQL_Injection',
                description: 'Comprehensive guide to preventing SQL injection'
            }
        ],
        cwe: '89'
    },
    xssVulnerability: {
        recommendation: 'Use proper content encoding and avoid direct DOM manipulation with user input. Implement Content Security Policy (CSP).',
        references: [
            {
                title: 'CWE-79: Cross-site Scripting',
                url: 'https://cwe.mitre.org/data/definitions/79.html',
                description: 'Understanding XSS vulnerabilities'
            },
            {
                title: 'OWASP XSS Prevention Cheat Sheet',
                url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                description: 'Detailed XSS prevention techniques'
            }
        ],
        cwe: '79'
    },
    bufferIssue: {
        recommendation: 'Use Buffer.alloc() instead of Buffer.allocUnsafe() or new Buffer(). Always initialize buffers safely.',
        references: [
            {
                title: 'CWE-119: Buffer Overflow',
                url: 'https://cwe.mitre.org/data/definitions/119.html',
                description: 'Understanding buffer overflow vulnerabilities'
            },
            {
                title: 'Node.js Buffer API Security',
                url: 'https://nodejs.org/api/buffer.html#buffer_buffer_alloc_size_fill_encoding',
                description: 'Official Node.js documentation on secure buffer usage'
            }
        ],
        cwe: '119'
    },
    memoryLeak: {
        recommendation: 'Always clear intervals and timeouts when they are no longer needed. Use cleanup functions in component unmount.',
        references: [
            {
                title: 'CWE-401: Memory Leak',
                url: 'https://cwe.mitre.org/data/definitions/401.html',
                description: 'Understanding memory leak vulnerabilities'
            }
        ],
        cwe: '401'
    },
    sensitiveData: {
        recommendation: 'Never expose sensitive data in code. Use secure storage and proper encryption for sensitive information.',
        references: [
            {
                title: 'CWE-200: Information Exposure',
                url: 'https://cwe.mitre.org/data/definitions/200.html',
                description: 'Understanding information exposure risks'
            },
            {
                title: 'OWASP Sensitive Data Exposure',
                url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
                description: 'OWASP guide on protecting sensitive data'
            }
        ],
        cwe: '200'
    },
    insecureTransmission: {
        recommendation: 'Use HTTPS for all data transmission. Implement proper SSL/TLS configuration.',
        references: [
            {
                title: 'CWE-319: Cleartext Transmission',
                url: 'https://cwe.mitre.org/data/definitions/319.html',
                description: 'Risks of cleartext data transmission'
            },
            {
                title: 'OWASP Transport Layer Protection',
                url: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet',
                description: 'Best practices for secure data transmission'
            }
        ],
        cwe: '319'
    }
};