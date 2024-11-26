# Plugin Vulnerability Scanner

A command-line security vulnerability scanner for plugin architectures, focusing on memory, filesystem, and plugin system vulnerabilities.

## Features

- Detects various types of security vulnerabilities:
  - Memory-related vulnerabilities (buffer overflows, memory leaks)
  - Filesystem vulnerabilities (path traversal, unsafe operations)
  - Plugin system vulnerabilities (unsafe loading, eval usage)
  - Event listener leaks
  - Unhandled file operations

## Installation

```bash
npm install -g plugin-vulnerability-scanner
```

## Usage

```bash
# Scan a single file
plugin-vulnerability-scanner scan path/to/file.js

# Output JSON format
plugin-vulnerability-scanner scan path/to/file.js --output json
```

## Example Output

```
Vulnerability Scan Report
========================

Summary:
Critical Issues: 2
High Issues: 1
Medium Issues: 3
Low Issues: 0
Total Issues: 6

CRITICAL Findings:
  unsafePluginLoad
  Description: Dynamic require() calls can lead to remote code execution
  File: test.js
  Line(s): 15, 23

  ...

Recommendations:
  bufferOverflow:
  Replace Buffer.allocUnsafe() with Buffer.alloc()

  ...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
