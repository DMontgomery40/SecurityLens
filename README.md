# Plugin Vulnerability Scanner

Scan JavaScript files or repositories for security vulnerabilities

<img src="screenshots/main-interface.png" alt="Main Scanner Interface" />

## Features

- Scan GitHub repositories directly via URL
- Upload and scan local JavaScript files
- Real-time vulnerability analysis
- Color-coded severity levels
- Detailed line-number references

## Usage

1. Enter a GitHub repository URL and click 'Scan URL'
   OR
2. Click 'Select Files' to analyze local JavaScript files

## Example Results

<img src="screenshots/scan-results.png" alt="Scan Results Example" />

The scanner identifies issues in several categories:

### Critical Findings
- Code injection vulnerabilities (eval usage)

### Medium Findings
- Buffer management issues
- Regular expression vulnerabilities

### Low Findings
- Development artifacts (console statements, debugger)

## Contributing

Contributions are welcome! Feel free to submit a Pull Request.

## License

MIT
