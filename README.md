# Plugin Vulnerability Scanner

A vulnerability scanner for plugin architectures, focusing on memory, filesystem, and plugin system vulnerabilities.
A comprehensive security vulnerability scanner for dependency management across multiple programming languages and package ecosystems. This tool helps identify security vulnerabilities in your project's dependencies, regardless of the programming language or package manager used.

https://dmontgomery40.github.io/plugin-vulnerability-scanner/

<p align="center">
  <a href="https://github.com/user-attachments/assets/c708b25e-ee33-45c8-baea-01e71a4061e8">
    <img src="https://private-user-images.githubusercontent.com/130489651/390199844-c708b25e-ee33-45c8-baea-01e71a4061e8.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzI2Njg5NDIsIm5iZiI6MTczMjY2ODY0MiwicGF0aCI6Ii8xMzA0ODk2NTEvMzkwMTk5ODQ0LWM3MDhiMjVlLWVlMzMtNDVjOC1iYWVhLTAxZTcxYTQwNjFlOC5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjQxMTI3JTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI0MTEyN1QwMDUwNDJaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT01NThlNzI2MTJhODFiYTk0ODQ1YmE1MGMyZmUwMDIyNjdhN2Q5NGU2NTBhZmYxNzk0ZjkzNTdjZTVlZmIwYzNlJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.vfCgiRbUTiLLhKYSaNco9YPuRR1ulskAxgMSvXm6Tjw" alt="Dashboard" width="45%"/>
  </a>
</p>




## Features

- Detects various types of security vulnerabilities:
  - Memory-related vulnerabilities (buffer overflows, memory leaks)
  - Filesystem vulnerabilities (path traversal, unsafe operations)
  - Plugin system vulnerabilities (unsafe loading, eval usage)
  - Event listener leaks
  - Unhandled file operations

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

## Features in Development
* Real-time vulnerability monitoring
* Custom rule creation
* Plugin ecosystem for custom checks
* Integration with additional package managers
* Enhanced CI/CD pipeline integration
* Custom policy enforcement
* Automated fix suggestions
* Impact analysis reports


### GitHub Actions

  ...
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
Recommendations:
  bufferOverflow:
  Replace Buffer.allocUnsafe() with Buffer.alloc()

### Jenkins Pipeline
  ...
```groovy
stage('Security Scan') {
  steps {
    sh 'plugin-vulnerability-scanner scan ./ --output json'
  }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
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

MIT
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## Support
* Documentation: [https://plugin-vulnerability-scanner.dev](https://plugin-vulnerability-scanner.dev)
* Issues: [GitHub Issues](https://github.com/DMontgomery40/plugin-vulnerability-scanner/issues)
* Discussions: [GitHub Discussions](https://github.com/DMontgomery40/plugin-vulnerability-scanner/discussions)
