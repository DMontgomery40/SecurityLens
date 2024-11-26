# Plugin Vulnerability Scanner

A security vulnerability scanner for plugin architectures, focusing on memory, filesystem, and plugin system vulnerabilities.

## Features

- Detects various types of security vulnerabilities:
  - Memory-related vulnerabilities (buffer overflows, memory leaks)
  - Filesystem vulnerabilities (path traversal, unsafe operations)
  - Plugin system vulnerabilities (unsafe loading, eval usage)
  - Event listener leaks
  - Unhandled file operations

- Provides detailed reports with:
  - Severity levels (Critical, High, Medium, Low)
  - File locations and line numbers
  - Vulnerability descriptions
  - Recommended fixes

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/DMontgomery40/plugin-vulnerability-scanner.git
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

## Usage

1. Click the 'Start Scan' button to begin scanning
2. The scanner will analyze the code for potential vulnerabilities
3. Results will be displayed with severity levels and recommendations

## Technologies Used

- React
- TailwindCSS
- Vite
- Lodash
- Lucide React Icons

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
