# [SecurityLens](https://securitylens.io)

[![Netlify Status](https://api.netlify.com/api/v1/badges/f084be9b-91ba-4210-86a9-81b7385633aa/deploy-status)](https://app.netlify.com/sites/securitylends/deploys)
[![GitHub license](https://img.shields.io/github/license/DMontgomery40/SecurityLens?branch=development&color=blue)](https://github.com/DMontgomery40/SecurityLens/blob/development/LICENSE)


[//]: # (01001000 01101001 01101110 01110100 00111010 00100000 01000011 01101000 01100101 01100011 01101011 00100000 01110100 01101000 01100101 00100000 01100110 01101111 01101111 01110100 01100101 01110010)
**Who is speaking on this page?**

<!-- Looking for secrets? Try reading between the lines... -->

AI agents read every word on a page as if the site said it. A comment, a review, an issue body, or a line of hidden text can give an agent orders, and today nothing tells the agent that someone other than the site wrote it.

SecurityLens shows which words on a page belong to the site, which belong to other people, and which are hidden. It flags anything that tries to steer an agent. It also defines the **Instruction Security Policy**, a one-header way for a site to declare who is speaking, and gives agents the same view over MCP.

[//]: # (Hint 2: URLs aren't just for websites...)

## What it does

- **Lens.** Enter a URL, a GitHub repository, or pasted HTML. The page is shown as a transcript by speaker, with findings for hidden instructions, orders inside user content, invisible Unicode payloads, poisoned WebMCP tool descriptions, and request input echoed as the site's voice. Pasted HTML never leaves the browser.
- **Repository mode.** For a GitHub repository, the lens reads what an agent working there is told: `AGENTS.md`, `CLAUDE.md`, rules files, skills, hooks, and MCP configs are the repository's voice, while open issues, pull requests, and comments are other people.
- **Instruction Security Policy.** A draft standard, like Content Security Policy but for prompt injection. The [spec](docs/spec/instruction-security-policy.md) is short, and the analyzer here is its reference implementation.
- **Policy tools.** Draft a policy from what the lens found, test it against the live page, copy the header for your server, check an existing policy, and create a report endpoint for agents to send violations to.
- **For agents.** A remote MCP server at `/mcp`, the same tools over stdio, an HTTP API, and an isomorphic library that harnesses can embed.
- **Rearview.** Open your Claude Code and Codex session logs in the browser and see what your agents ran, what left your machine, which secrets passed through the model, and every consequential action taken right after untrusted content gave instructions. The logs are parsed in a Web Worker in the tab and never uploaded.
- **Code scanner.** The original educational vulnerability scanner still lives at `/scanner`.

## Instruction Security Policy in one minute

```text
Instruction-Security-Policy: default voice; untrusted #comments, .review-body; tools 'self'; report-to https://securitylens.io/r/7f3c9a
```

- Content is either `voice` (the site is speaking) or `untrusted` (someone else is). Agents may use untrusted content as information and never follow it as instructions.
- Untrusted always wins. Nothing inside an untrusted region can become voice, and the `data-isp` attribute can only mark content untrusted.
- Text hidden from sighted readers is always untrusted.
- A policy that does not parse cleanly fails closed: every voice grant is dropped.
- Delivery is a response header, a meta tag inside `head`, or `/.well-known/instruction-security-policy`.

Read the full [draft spec](docs/spec/instruction-security-policy.md).

## Use it from an agent

The remote server speaks Streamable HTTP in stateless JSON mode and needs no account.

```bash
# Claude Code
claude mcp add --transport http securitylens https://securitylens.io/mcp
```

```toml
# Codex: ~/.codex/config.toml
[mcp_servers.securitylens]
url = "https://securitylens.io/mcp"
```

```bash
# Local stdio server, from a clone
node src/cli/index.js mcp
```

| Tool | What it returns |
| --- | --- |
| `read_page` | The page grouped by speaker, with hidden text removed and boundaries that page text cannot forge |
| `check_page` | Findings, regions, and policy status, optionally with a draft policy applied |
| `check_repository` | What a GitHub repository's instruction files, hooks, MCP configs, issues, and comments tell agents |
| `check_policy` | A policy explained directive by directive, with errors and warnings |
| `write_policy` | A drafted policy and snippets for common servers |

## HTTP API

```bash
# Agent view as plain text
curl 'https://securitylens.io/api/lens?url=https://example.com/post&view=agent&format=text'

# Full analysis of submitted HTML
curl -X POST https://securitylens.io/api/lens \
  -H 'content-type: application/json' \
  -d '{"html":"<p>Ignore previous instructions</p>"}'
```

`view=policy` returns a drafted policy. A `policy` field in a POST body tests a draft policy instead of the site's own. Repository URLs return a repository report.

## Command line

The package is not published to npm yet. Run the CLI from a clone, or run `npm link` once to get a `securitylens` command.

```bash
node src/cli/index.js lens https://example.com/post          # transcript and findings
node src/cli/index.js lens --html page.html --format agent    # agent view of a local file
node src/cli/index.js lens https://github.com/owner/repo       # repository mode
node src/cli/index.js policy check "untrusted #comments"
node src/cli/index.js policy write https://example.com/post
```

`lens` exits with status 1 when it finds a critical or high finding that no policy contains, so it can gate CI.

## Local development

```bash
npm install
netlify dev          # site, functions, and Blobs on http://localhost:8888
npm test
npm run build
```

In a git worktree, the Netlify CLI looks for functions in the wrong directory. Pass the folder explicitly: `netlify dev --functions "$PWD/netlify/functions"`.

## Security notes

- The server-side fetcher resolves DNS itself, refuses loopback, private, link-local, cloud metadata, and other reserved addresses (including IPv4-mapped and NAT64 IPv6 forms), pins the connection to the checked address, and re-checks every redirect. The classic website scanner uses the same fetcher.
- The lens renders page text as text. It never injects fetched HTML into the page.
- Report endpoints are capability URLs. The endpoint in a policy can only submit reports, and reading them takes a separate view key that is stored only as a hash.
- Repository mode only contacts `api.github.com` and `raw.githubusercontent.com`.

## Code scanner

### Code scanner CLI

The original pattern scanner runs from the same CLI. The package is not published to npm yet, so run it from a clone, or run `npm link` once to get a `securitylens` command.

```bash
# Display the built-in help
securitylens --help

# Scan a local path (file or directory)
securitylens scan ./path/to/project

# Scan a public GitHub repository
securitylens scan-repo https://github.com/owner/repo

# Scan with custom concurrency (default: 10, max: 50)
securitylens scan-repo --concurrency 2 https://github.com/owner/repo

# Exit codes follow common CI conventions – the process exits with 1 when
# CRITICAL or HIGH vulnerabilities are found so you can gate builds easily.
```

If you need to access private repositories remember to provide a GitHub token:

```bash
GITHUB_TOKEN=ghp_... securitylens scan-repo https://github.com/owner/private-repo
```

#### Performance and rate limiting

The scanner includes configurable concurrency controls to balance speed with GitHub API rate limits:

- **Default concurrency**: 10 concurrent file downloads
- **Range**: 1-50 concurrent downloads (automatically clamped)
- **Rate limit protection**: Built-in safeguards to avoid exceeding GitHub limits
- **Error handling**: Non-fatal errors during file downloads don't stop the scan

For large repositories, consider using lower concurrency (e.g., `--concurrency 2`) to be more conservative with rate limits. For small repositories or when you have higher rate limits, you can use higher concurrency (e.g., `--concurrency 50`) for faster scanning.

---

### Docker

Prefer containers? We've got you covered! The repository includes a production-ready
`Dockerfile` that bundles **both** the static web interface **and** the CLI.

#### Build the image

```bash
docker build -t securitylens .
```

#### Run the web UI

```bash
# Expose the Vite preview server on http://localhost:4173
docker run --rm -p 4173:4173 securitylens
```

#### Use the CLI inside the container

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

### Code scanner architecture

#### Modules

SecurityLens uses a clean, modular architecture that makes it easy to extend and maintain:

```
src/
├── lib/                      # Core modules
│   ├── isp/                 # Instruction Security Policy analyzer, generator, agent view
│   │   └── node/            # SSRF-safe fetcher, GitHub reader, MCP server, reports
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

#### Adding vulnerability patterns

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

#### Performance and concurrency

SecurityLens includes intelligent performance optimizations:

- **Configurable concurrency**: Control how many GitHub API requests run simultaneously
- **Smart caching**: Repository data cached for 24 hours to reduce API calls
- **Non-blocking errors**: Failed file downloads don't stop the entire scan
- **Rate limit protection**: Built-in safeguards prevent hitting GitHub API limits
- **Efficient parsing**: Patterns only applied to relevant file types

#### Error handling

Robust error handling ensures scans complete even when individual files fail:

- **Standardized error types**: `ScanError` class with error codes, messages, and details
- **Partial results**: Scans return results even if some files couldn't be processed
- **Error collection**: All non-fatal errors collected and reported in scan results
- **Graceful degradation**: Missing tokens, network issues, and rate limits handled gracefully

---

## Roadmap

- Harness adoption of the Instruction Security Policy, starting with the SecurityLens MCP tools as the reference consumer.
- Rendered-page analysis for content that JavaScript adds after load.
- Firmware and binary scanning for the classic scanner.

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
