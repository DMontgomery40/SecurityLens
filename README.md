# Plugin Vulnerability Scanner

A specialized security scanner that analyzes JavaScript code for potential vulnerabilities and dangerous coding patterns. The scanner performs static analysis to identify issues ranging from critical security vulnerabilities to production-ready code quality concerns.

## What It Scans For

### Critical Severity
- eval() usage that could enable code injection attacks

### Medium Severity
- Buffer overflow vulnerabilities (Buffer.allocUnsafe())
- Unsafe regex patterns that could lead to ReDos attacks

### Low Severity
- Console statements in production code
- Debugger statements that should be removed

## Usage

```bash
# Scan a URL
Enter a GitHub repository URL in the input field and click 'Scan URL'

# Scan local files
Click 'Select Files' and choose the JavaScript files you want to analyze
```

## Example Output

The scanner provides a detailed report categorizing findings by severity level:

```
Summary:
Critical: 2
High: 0
Medium: 4
Low: 3

Findings include:
- File locations (src/index.js, src/lib/scanner.js, etc)
- Line numbers for each issue
- Detailed descriptions of the problems
- Specific recommendations for fixing each type of issue
```

## Recommendations

The tool provides specific guidance for fixing each type of issue:

- evalUsage: Replace eval() with safer alternatives like JSON.parse() or Function()
- bufferOverflow: Use Buffer.alloc() instead of Buffer.allocUnsafe()
- unsafeRegex: Use static regular expressions or validate dynamic patterns
- consoleUsage: Remove console statements or use a logging library
- debuggerStatement: Remove debugger statements before deploying to production

## Contributing

Contributions are welcome! Feel free to submit a Pull Request.

## License

MIT
