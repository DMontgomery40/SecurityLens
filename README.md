# Plugin Vulnerability Scanner

A comprehensive security vulnerability scanner for dependency management across multiple programming languages and package ecosystems. This tool helps identify security vulnerabilities in your project's dependencies, regardless of the programming language or package manager used.

## Features

### Multi-Language Support
Analyzes dependencies and vulnerabilities across multiple package ecosystems:
* JavaScript/Node.js (npm)
* Python (pip, poetry)
* Ruby (gem)
* Java (Maven, Gradle)
* PHP (Composer)
* Go (go modules)
* Rust (Cargo)

### Vulnerability Detection
* Dependency vulnerability scanning
* Version compatibility checking
* Known CVE detection
* Outdated package identification
* License compliance checking
* Security advisory integration

### Analysis Types
* Deep dependency tree analysis
* Transitive dependency checking
* Supply chain vulnerability detection
* Package integrity verification
* Version constraint validation

### Output Formats
* JSON
* Plain text
* HTML reports
* GitHub-flavored Markdown
* CI/CD compatible formats

## Installation

```bash
# Install globally via npm
npm install -g plugin-vulnerability-scanner

# Or run directly with npx
npx plugin-vulnerability-scanner
```

## Usage

```bash
# Basic scan of a project directory
plugin-vulnerability-scanner scan ./path/to/project

# Scan with specific output format
plugin-vulnerability-scanner scan ./path/to/project --output json

# Scan specific package managers
plugin-vulnerability-scanner scan ./path/to/project --ecosystem npm,pip

# Generate detailed HTML report
plugin-vulnerability-scanner scan ./path/to/project --output html --report-file report.html

# Continuous Integration mode
plugin-vulnerability-scanner scan --ci
```

### Configuration

Create a `.scannerrc` or `scanner.config.json` file to customize behavior:

```json
{
  "ignorePatterns": ["**/node_modules/**", "**/vendor/**"],
  "severityThreshold": "medium",
  "ecosystems": ["npm", "pip", "gem"],
  "outputFormat": "json",
  "failOnIssues": true
}
```

## Example Output

```
📊 Vulnerability Scan Report
===========================

📍 Project: my-application
📅 Scan Date: 2024-03-26 14:30:00

📈 Summary:
├── Critical Issues: 2
├── High Issues: 3
├── Medium Issues: 5
├── Low Issues: 1
└── Total Issues: 11

🛑 Critical Findings:
  
  1. Critical Severity in lodash (npm)
     CVE-2021-23337: Prototype Pollution
     Affected versions: <4.17.21
     Current version: 4.17.15
     Recommendation: Upgrade to 4.17.21 or later

  2. Critical Severity in django (pip)
     CVE-2023-23969: SQL Injection
     Affected versions: <4.2.1
     Current version: 4.1.0
     Recommendation: Upgrade to 4.2.1 or later

💡 Recommendations:
  
  1. Update vulnerable packages:
     npm update lodash@4.17.21
     pip install django==4.2.1

  2. Review dependency update impact
  3. Run tests after updates
  4. Monitor security advisories
```

## Features in Development

* Real-time vulnerability monitoring
* Custom rule creation
* Plugin ecosystem for custom checks
* Integration with additional package managers
* Enhanced CI/CD pipeline integration
* Custom policy enforcement
* Automated fix suggestions
* Impact analysis reports

## Integration

### GitHub Actions

```yaml
- name: Security Scan
  uses: plugin-vulnerability-scanner/action@v1
  with:
    path: '.'
    fail-on: 'high'
```

### GitLab CI

```yaml
security_scan:
  image: plugin-vulnerability-scanner
  script:
    - plugin-vulnerability-scanner scan ./ --ci
```

### Jenkins Pipeline

```groovy
stage('Security Scan') {
  steps {
    sh 'plugin-vulnerability-scanner scan ./ --output json'
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Here's how you can contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/yourusername/plugin-vulnerability-scanner.git
cd plugin-vulnerability-scanner
npm install
npm run dev
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

* Documentation: [https://plugin-vulnerability-scanner.dev](https://plugin-vulnerability-scanner.dev)
* Issues: [GitHub Issues](https://github.com/DMontgomery40/plugin-vulnerability-scanner/issues)
* Discussions: [GitHub Discussions](https://github.com/DMontgomery40/plugin-vulnerability-scanner/discussions)
