// Core vulnerability patterns
export const VULNERABILITY_PATTERNS = {
    // Memory-related vulnerabilities
    bufferOverflow: {
        pattern: /Buffer\.allocUnsafe\(|new\s+Buffer\(/,
        description: 'Potential buffer overflow vulnerability',
        severity: 'HIGH',
        remediation: 'Use Buffer.alloc() instead of Buffer.allocUnsafe() or new Buffer()'
    },
    memoryLeak: {
        pattern: /(setInterval|setTimeout)\s*\(\s*[^,]+\s*,\s*[^)]+\)/,
        description: 'Potential memory leak in timer/interval',
        severity: 'MEDIUM',
        remediation: 'Ensure all intervals/timeouts are properly cleared'
    },

    // Filesystem vulnerabilities  
    pathTraversal: {
        pattern: /\.\.(\/|\\)|\/\/|\\\\/,
        description: 'Path traversal vulnerability detected',
        severity: 'CRITICAL',
        remediation: 'Validate and sanitize all file paths'
    },
    unsafeFileOps: {
        pattern: /fs\.(read|write)FileSync/,
        description: 'Unsafe synchronous file operation',
        severity: 'MEDIUM',
        remediation: 'Use asynchronous file operations'
    },

    // Code execution vulnerabilities
    eval: {
        pattern: /eval\(|new\s+Function\(|setTimeout\(\s*["']|setInterval\(\s*["']/,
        description: 'Dangerous code execution detected',
        severity: 'CRITICAL',
        remediation: 'Avoid using eval() or new Function()'
    },
    commandInjection: {
        pattern: /child_process\.exec\(|\.exec\(|\.spawn\(/,
        description: 'Potential command injection vulnerability',
        severity: 'CRITICAL',
        remediation: 'Validate and sanitize all command inputs'
    },

    // Data vulnerabilities
    sqlInjection: {
        pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\bFROM\b|\bINTO\b|\bWHERE\b).*(\?|'|")/i,
        description: 'Potential SQL injection vulnerability',
        severity: 'CRITICAL',
        remediation: 'Use parameterized queries or an ORM'
    },
    xss: {
        pattern: /innerHTML|outerHTML|document\.write|\$\(.*\)\.html\(/,
        description: 'Cross-site scripting vulnerability',
        severity: 'HIGH',
        remediation: 'Use innerText or textContent instead'
    },
    
    // Configuration vulnerabilities
    hardcodedSecrets: {
        pattern: /(api[_-]?key|secret|password|credential)["\s]*[:=]["\s]*['"][^'"]+['"]/,
        description: 'Hardcoded secret/credential detected',
        severity: 'CRITICAL',
        remediation: 'Move secrets to environment variables'
    },
    insecureCrypto: {
        pattern: /crypto\.createHash\(['"]md5['"]\)|crypto\.createHash\(['"]sha1['"]\)/,
        description: 'Use of weak cryptographic algorithm',
        severity: 'HIGH',
        remediation: 'Use strong algorithms like SHA-256 or higher'
    },

    // Plugin system vulnerabilities
    dynamicRequire: {
        pattern: /require\(\s*[^'"][^)]*\)|import\s*\(\s*[^'"][^)]*\)/,
        description: 'Dynamic module loading detected',
        severity: 'HIGH',
        remediation: 'Use static imports/requires with literal paths'
    },
    unsafeDeserialization: {
        pattern: /JSON\.parse\(|deserialize\(|fromJSON\(/,
        description: 'Potential unsafe deserialization',
        severity: 'HIGH',
        remediation: 'Validate JSON schema before parsing'
    },

    // React-specific vulnerabilities
    dangerouslySetInnerHTML: {
        pattern: /dangerouslySetInnerHTML/,
        description: 'Dangerous innerHTML usage in React',
        severity: 'HIGH',
        remediation: 'Use safe alternatives like textContent or sanitize HTML'
    },
    unsafeRefs: {
        pattern: /useRef\(\s*null\s*\)|React\.createRef\(\s*\)/,
        description: 'Potentially unsafe React ref usage',
        severity: 'MEDIUM',
        remediation: 'Ensure refs are properly managed and cleaned up'
    },

    // Node.js specific vulnerabilities
    nodePrototypePollution: {
        pattern: /Object\.assign\(\s*{}\s*,|\.\.\.[^{]*$/m,
        description: 'Potential prototype pollution',
        severity: 'HIGH',
        remediation: 'Use Object.create(null) or sanitize object inputs'
    },
    unsafeRegex: {
        pattern: /new RegExp\(|\/.*\*\+/,
        description: 'Potentially unsafe regular expression',
        severity: 'MEDIUM',
        remediation: 'Validate regex patterns and avoid user input in regex'
    }
};