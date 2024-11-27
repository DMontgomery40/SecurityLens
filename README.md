# Plugin Vulnerability Scanner

A security vulnerability scanner for dependency management, currently focused on JavaScript/Node.js projects with plans to expand to other languages.

## Current Status

🚧 **Early Development** 🚧

This project is currently in active development. Here's what's working now:

* JavaScript/Node.js dependency scanning
* Basic vulnerability detection
* Command-line interface
* JSON and plain text output formats

## Roadmap

Future plans include support for:
* Additional programming languages (Python, Ruby, Java, etc.)
* Enhanced vulnerability detection
* Web interface
* CI/CD integration
* Custom rules and policies

## Installation

```bash
# Install globally via npm
npm install -g plugin-vulnerability-scanner

# Or run directly with npx
npx plugin-vulnerability-scanner
```

## Usage

```bash
# Basic scan of a project
plugin-vulnerability-scanner scan ./path/to/project

# Scan with JSON output
plugin-vulnerability-scanner scan ./path/to/project --output json
```

## Example Output

```
Vulnerability Scan Report
========================

Summary:
Critical Issues: 1
High Issues: 2
Medium Issues: 1
Low Issues: 0
Total Issues: 4

Critical Findings:
  1. Prototype Pollution in lodash
     CVE-2021-23337
     Affected versions: <4.17.21
     Current version: 4.17.15
     Recommendation: Upgrade to 4.17.21 or later

Recommendations:
  1. Update vulnerable packages
  2. Run tests after updates
```

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/cool-new-thing`)
3. Commit your changes (`git commit -m 'Add some cool new thing'`)
4. Push to the branch (`git push origin feature/cool-new-thing`)
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

* Issues: [GitHub Issues](https://github.com/DMontgomery40/plugin-vulnerability-scanner/issues)
* Discussions: [GitHub Discussions](https://github.com/DMontgomery40/plugin-vulnerability-scanner/discussions)
