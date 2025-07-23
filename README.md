# [SecurityLens](https://securitylens.io)

[![Netlify Status](https://api.netlify.com/api/v1/badges/f084be9b-91ba-4210-86a9-81b7385633aa/deploy-status)](https://app.netlify.com/sites/securitylends/deploys)
[![GitHub license](https://img.shields.io/github/license/DMontgomery40/SecurityLens?branch=development&color=blue)](https://github.com/DMontgomery40/SecurityLens/blob/development/LICENSE)


[//]: # (01001000 01101001 01101110 01110100 00111010 00100000 01000011 01101000 01100101 01100011 01101011 00100000 01110100 01101000 01100101 00100000 01100110 01101111 01101111 01110100 01100101 01110010)
**Because everyone should be able to explore cybersecurity—no fancy tools or gatekeeping required.**

> **Your Journey into Security Starts Here!**  
<!-- Looking for secrets? Try reading between the lines... -->

> Ever wondered how hackers find vulnerabilities? Want to learn how to protect websites and apps? You're in the right place! Drop in your code or website, and let's discover security together in a way that's fun, practical, and *totally* beginner-friendly.

---

## What is SecurityLens?
[//]: # (Hint 2: URLs aren't just for websites...)

SecurityLens is an educational tool designed to **bridge the gap** between curious minds and real-world security concepts. No need for advanced command-line skills or pricey security suites. If you can paste a link or drag a file, you're good to go!

### Why This Matters
- **Security should be accessible**: Tools like Kali Linux or Burp Suite can feel daunting to a newcomer.
- **Hands-on learning**: We believe you learn better by *trying* things, not just reading about them.
- **Next-gen security pros**: We need more people (of all ages!) excited about protecting digital spaces.

---

## How It Works

1. **Scan a GitHub Repo**: Paste in the URL of an open-source project or your personal repo.
2. **Check a Live Website**: Curious if a site has potential issues? Enter the address—no special setup needed.
3. **Analyze Local Code**: Drag and drop files from your machine to see what might be lurking in your own projects.
4. **Firmware/Binary (Coming Soon!)**: We're working on a mini-lab approach to help you peek inside binaries without advanced tools.

---

## Understanding Your Discoveries

When you run a scan, you'll see potential issues sorted by **severity**:

- **CRITICAL**:  
  Whoa! Immediate attention needed—like leaving your front door wide open!  
- **HIGH**:  
  Serious stuff—like a weak lock that a determined intruder could easily crack.  
- **MEDIUM**:  
  Worth fixing—think of it as upgrading old locks to sturdier ones.  
- **LOW**:  
  Good practice—like adding a camera to an already secure house. Always nice to have.

Each finding includes a quick explanation of **why** it matters, some **code examples**, multipe **references** to learn more,and **tips** to fix it—so you can learn and apply that knowledge going forward.

---

## Pro Tips for New Security Researchers

- **Look deeper**: Don't just stop at the first warning. Real security experts always ask *"Why?"*  
- **Examine the code**: Our examples show you *exactly* where vulnerabilities might lurk.  
- **Explore solutions**: We provide "safe" snippets or pointers to help you patch issues effectively.  
- **No gatekeeping**: If you don't know a term, no worries! That's why we're here—to make it clear and approachable.

---

## Quick Start (Local Dev)

```bash
# 1. Clone the repository
git clone https://github.com/DMontgomery40/SecurityLens.git

# 2. Install dependencies
npm install

# 3. Run the development server
npm run dev

# 4. Build for production
npm run build
```

Open the app in your browser, and you're off to the races. No advanced CLI wizardry needed—just your curiosity!

---

## Command-Line Scanner

SecurityLens also ships with a fully-featured CLI that you can use outside of the web UI.

```bash
# Display the built-in help
npx securitylens --help

# Scan a local path (file or directory)
npx securitylens scan ./path/to/project

# Scan a public GitHub repository
npx securitylens scan-repo https://github.com/owner/repo

# Scan with custom concurrency (default: 10, max: 50)
npx securitylens scan-repo --concurrency 2 https://github.com/owner/repo

# Exit codes follow common CI conventions – the process exits with 1 when
# CRITICAL or HIGH vulnerabilities are found so you can gate builds easily.
```

If you need to access private repositories remember to provide a GitHub token:

```bash
GITHUB_TOKEN=ghp_... npx securitylens scan-repo https://github.com/owner/private-repo
```

### Performance & Rate Limiting

The scanner includes configurable concurrency controls to balance speed with GitHub API rate limits:

- **Default concurrency**: 10 concurrent file downloads
- **Range**: 1-50 concurrent downloads (automatically clamped)
- **Rate limit protection**: Built-in safeguards to avoid exceeding GitHub limits
- **Error handling**: Non-fatal errors during file downloads don't stop the scan

For large repositories, consider using lower concurrency (e.g., `--concurrency 2`) to be more conservative with rate limits. For small repositories or when you have higher rate limits, you can use higher concurrency (e.g., `--concurrency 50`) for faster scanning.

---

## Docker Support 🚢

Prefer containers? We've got you covered! The repository includes a production-ready
`Dockerfile` that bundles **both** the static web interface **and** the CLI.

### 1. Build the image

```bash
docker build -t securitylens .
```

### 2. Run the web UI

```bash
# Expose the Vite preview server on http://localhost:4173
docker run --rm -p 4173:4173 securitylens
```

### 3. Use the CLI inside the container

```bash
# Show help
docker run --rm securitylens securitylens --help

# Scan the current folder (mount it inside the container)
docker run --rm -v "$(pwd)":/workspace securitylens \
  securitylens scan /workspace

# Scan a GitHub repo with a token
docker run --rm -e GITHUB_TOKEN=$GITHUB_TOKEN securitylens \
  securitylens scan-repo https://github.com/owner/repo
```

Because the CLI is the container's **entrypoint command**, anything that comes
after the image name is forwarded directly to `securitylens`. Feel free to pass
all the regular flags shown in the examples above.

---

## Architecture & Development

### Modular Architecture

SecurityLens uses a clean, modular architecture that makes it easy to extend and maintain:

```
src/
├── lib/                      # Core scanning modules
│   ├── RepositoryCrawler.js  # GitHub API integration with concurrency control
│   ├── FileScanner.js        # File content analysis orchestrator  
│   ├── ReportBuilder.js      # Report generation and formatting
│   ├── scanner.js           # Legacy scanner (being phased out)
│   ├── patterns/            # Vulnerability detection patterns
│   │   ├── index.js         # Pattern registry and loader
│   │   ├── injection.js     # SQL/Command injection patterns
│   │   ├── authentication.js# Auth and session vulnerabilities
│   │   ├── cryptography.js  # Crypto-related weaknesses
│   │   ├── api.js           # API security patterns
│   │   └── ...              # Additional pattern categories
│   ├── cache/               # Intelligent caching system
│   └── utils.js            # Shared utilities
├── components/              # React UI components
├── cli/                     # Command-line interface
└── context/                # React state management
```

### Adding New Vulnerability Patterns

SecurityLens makes it easy to add new security checks. All patterns are organized by category in `src/lib/patterns/`:

1. **Choose or create a category file** (e.g., `src/lib/patterns/api.js`)
2. **Add your pattern** following this structure:

```javascript
export const myNewPattern = {
  id: 'myNewVulnerability',
  name: 'My New Vulnerability',
  description: 'Description of what this detects',
  severity: 'HIGH', // CRITICAL, HIGH, MEDIUM, LOW
  pattern: /your-regex-pattern/i,
  category: 'API Security',
  cwe: '123' // Common Weakness Enumeration ID
};
```

3. **Export it in the category file**:
```javascript
export const apiPatterns = [
  myNewPattern,
  // ... other patterns
];
```

4. **Register the category** in `src/lib/patterns/index.js`:
```javascript
import { apiPatterns } from './api.js';

export const allPatterns = [
  ...apiPatterns,
  // ... other pattern groups
];
```

That's it! Your new pattern will automatically be included in scans across CLI, web UI, and Netlify functions.

### Performance & Concurrency

SecurityLens includes intelligent performance optimizations:

- **Configurable concurrency**: Control how many GitHub API requests run simultaneously
- **Smart caching**: Repository data cached for 24 hours to reduce API calls
- **Non-blocking errors**: Failed file downloads don't stop the entire scan
- **Rate limit protection**: Built-in safeguards prevent hitting GitHub API limits
- **Efficient parsing**: Patterns only applied to relevant file types

### Error Handling

Robust error handling ensures scans complete even when individual files fail:

- **Standardized error types**: `ScanError` class with error codes, messages, and details
- **Partial results**: Scans return results even if some files couldn't be processed
- **Error collection**: All non-fatal errors collected and reported in scan results
- **Graceful degradation**: Missing tokens, network issues, and rate limits handled gracefully

---

## Roadmap

### Now
- Basic vulnerability scanning  
- Educational how-to-fix guides  
- GitHub integration  

### Up Next
- Firmware/binary scanning in a mini-lab environment  
- Interactive tutorials & challenges  
- More advanced patterns & "cheat codes" for security  

---

## Contributing & Community

We want your input—whether you're a seasoned dev or just got your first "Hello, World!":

- Have ideas for new vulnerability checks? Let us know!  
- Found a bug? [Open an issue](https://github.com/DMontgomery40/SecurityLens/issues).  
- Want to make it better? PRs welcome.

Check out our [CONTRIBUTING.md](CONTRIBUTING.md) for more on how to get involved.

---

## License

Distributed under the [MIT License](LICENSE). Because knowledge—and security—should be free for everyone.

---

<p align="center">
  Built by people who remember what it's like to be beginners, 
  for the next generation of security heroes.
</p>  



[//]: # (Q29uZ3JhdHMhIFlvdSd2ZSBmb3VuZCB0aGUgc2VjcmV0IG1lc3NhZ2UuIFlvdSdyZSB0aGlua2luZyBsaWtlIGEgc2VjdXJpdHkgcmVzZWFyY2hlciBhbHJlYWR5ISA8MyBLZWVwIGV4cGxvcmluZy4uLg==)

[//]: # (https://securitylens.io/secret?message=)
