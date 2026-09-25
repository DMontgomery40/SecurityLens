// Repository mode: who tells an agent what to do inside a code repository.
// Instruction files (AGENTS.md, CLAUDE.md, rules, skills) are the repo's own
// voice. Issues, pull requests, and comments are other people. Hooks and MCP
// configs are automation the repo offers to agents.

import { analyzeText, detectInstructions, normalizeForMatching } from './detect.js';
import { SEVERITIES } from './analyze.js';

const INSTRUCTION_PATTERNS = [
  /(^|\/)AGENTS\.md$/,
  /(^|\/)CLAUDE\.md$/,
  /(^|\/)GEMINI\.md$/,
  /(^|\/)\.(cursorrules|windsurfrules|clinerules)$/,
  /^\.github\/copilot-instructions\.md$/,
  /^\.github\/instructions\/[^/]+\.instructions\.md$/,
  /(^|\/)\.cursor\/rules\/.+\.mdc?$/,
  /(^|\/)SKILL\.md$/,
  /(^|\/)\.claude\/(commands|agents)\/.+\.md$/
];
const MCP_CONFIG_PATTERNS = [/(^|\/)\.mcp\.json$/, /^\.vscode\/mcp\.json$/, /^\.cursor\/mcp\.json$/];
const SETTINGS_PATTERNS = [/^\.claude\/settings(\.local)?\.json$/];

export function classifyPath(path) {
  if (INSTRUCTION_PATTERNS.some((pattern) => pattern.test(path))) return 'instructions';
  if (MCP_CONFIG_PATTERNS.some((pattern) => pattern.test(path))) return 'mcp-config';
  if (SETTINGS_PATTERNS.some((pattern) => pattern.test(path))) return 'agent-settings';
  return null;
}

const NAME = /^[A-Za-z0-9_.-]+$/;

export function parseGitHubRepoUrl(input) {
  let url;
  try {
    url = new URL(/^https?:\/\//i.test(String(input).trim()) ? String(input).trim() : `https://${String(input).trim()}`);
  } catch {
    return null;
  }
  if (!['github.com', 'www.github.com'].includes(url.hostname.toLowerCase())) return null;
  const [owner, rawRepo, ...rest] = url.pathname.split('/').filter(Boolean);
  if (!owner || !rawRepo) return null;
  if (rest.length > 0 && rest[0] !== 'tree') return null;
  const repo = rawRepo.replace(/\.git$/, '');
  if (!NAME.test(owner) || !NAME.test(repo)) return null;
  return { owner, repo };
}

function excerpt(text, length = 320) {
  const clean = normalizeForMatching(text);
  return clean.length > length ? `${clean.slice(0, length)}…` : clean;
}

// Split markdown into visible text and HTML comments, which GitHub hides from
// readers but agents reading the raw text still see.
export function splitMarkdown(text) {
  const parts = [];
  const pattern = /<!--([\s\S]*?)-->/g;
  let last = 0;
  let match;
  while ((match = pattern.exec(text))) {
    if (match.index > last) parts.push({ hidden: false, text: text.slice(last, match.index) });
    parts.push({ hidden: true, text: match[1] });
    last = match.index + match[0].length;
  }
  if (last < text.length) parts.push({ hidden: false, text: text.slice(last) });
  return parts.map((part) => ({ ...part, text: part.text.trim() })).filter((part) => part.text);
}

const PAYLOAD_KINDS = new Set(['unicode-tags', 'variation-selectors', 'zero-width']);
const RISKY_RULES = new Set(['exfiltration', 'secrecy']);

function analyzeMarkdown(text, { visibleZone, location, url, owner }) {
  const segments = [];
  const findings = [];
  const whole = analyzeText(text);
  const payloads = whole.smuggling.kinds.filter((kind) => PAYLOAD_KINDS.has(kind.kind));

  if (payloads.length) {
    const instructive = whole.matches.some((match) => match.via === 'invisible-unicode');
    findings.push({
      kind: 'invisible-payload',
      severity: instructive ? 'critical' : 'high',
      title: 'Invisible text payload',
      detail: `${payloads.map((kind) => kind.label).join(' and ')} carry a message that people reviewing ${location} cannot see.`,
      decoded: whole.smuggling.decoded.slice(0, 600),
      decodedFrom: 'invisible-unicode',
      remediation: 'Remove the invisible characters and review who added them.'
    });
  }

  for (const part of splitMarkdown(text)) {
    if (part.hidden) {
      segments.push({ zone: 'hidden', hiddenKind: 'html-comment', text: part.text });
      const analysis = analyzeText(part.text);
      if (analysis.strength !== 'none') {
        findings.push({
          kind: 'hidden-instruction',
          severity: analysis.strength === 'strong' ? 'critical' : 'high',
          title: 'Instructions hidden in an HTML comment',
          detail: `GitHub does not show HTML comments to people reading ${location}, but agents reading the raw text do.`,
          excerpt: excerpt(part.text),
          rules: analysis.matches.map(({ rule, label }) => ({ rule, label })),
          remediation: 'Remove the comment and review who added it.'
        });
      }
      continue;
    }

    segments.push({ zone: visibleZone, text: part.text });
    const analysis = detectInstructions(part.text);
    if (visibleZone === 'voice') {
      const risky = analysis.matches.filter((match) => RISKY_RULES.has(match.rule));
      const markers = analysis.matches.filter((match) => match.rule === 'role-marker');
      if (risky.length || markers.length) {
        findings.push({
          kind: 'instruction-file-risky-rule',
          severity: risky.length ? 'high' : 'medium',
          title: risky.length ? `${location} asks agents to ${risky[0].rule === 'secrecy' ? 'hide something from their user' : 'send data somewhere'}` : `${location} contains fake system markers`,
          detail: `Agents follow ${location} as the repository's own instructions, so this rule would run with the repository's authority.`,
          excerpt: (risky[0] || markers[0]).excerpt || excerpt(part.text),
          rules: [...risky, ...markers].map(({ rule, label }) => ({ rule, label })),
          remediation: 'Remove the rule and review the file history.'
        });
      }
    } else if (analysis.strength !== 'none') {
      findings.push({
        kind: 'instruction-in-untrusted',
        severity: analysis.strength === 'strong' ? (analysis.quoted ? 'medium' : 'high') : 'low',
        contained: false,
        quoted: analysis.quoted,
        title: analysis.strength === 'strong' ? (analysis.quoted ? 'Quoted instructions inside user content' : 'Instructions inside user content') : 'Instruction-like wording in user content',
        detail: `${owner ? `@${owner}` : 'Someone'} wrote this in ${location}. Agents that triage issues or review pull requests read it alongside the maintainers' own words.`,
        excerpt: [...analysis.matches].sort((a, b) => b.weight - a.weight)[0]?.excerpt || excerpt(part.text),
        rules: analysis.matches.map(({ rule, label }) => ({ rule, label })),
        remediation: 'Hide or edit the text, and make sure agents working on issues treat issue text as untrusted.'
      });
    }
  }

  return { segments, findings: findings.map((finding) => ({ ...finding, location, url: url || null })) };
}

function parseJson(text) {
  try {
    return { value: JSON.parse(text), error: null };
  } catch {
    return { value: null, error: 'The file is not valid JSON.' };
  }
}

function analyzeConfig(file) {
  const kind = classifyPath(file.path);
  const { value, error } = parseJson(file.text);
  const config = { path: file.path, kind, servers: [], hooks: [], error };
  if (!value || typeof value !== 'object') return config;

  const servers = value.mcpServers || value.servers || {};
  if (servers && typeof servers === 'object') {
    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      const command = typeof server.command === 'string' ? [server.command, ...(Array.isArray(server.args) ? server.args : [])].join(' ') : null;
      config.servers.push({ name, command, url: typeof server.url === 'string' ? server.url : null });
    }
  }

  if (value.hooks && typeof value.hooks === 'object') {
    for (const [event, entries] of Object.entries(value.hooks)) {
      for (const entry of Array.isArray(entries) ? entries : []) {
        for (const hook of Array.isArray(entry?.hooks) ? entry.hooks : []) {
          if (hook?.type === 'command' && typeof hook.command === 'string') config.hooks.push({ event, command: hook.command });
        }
      }
    }
  }

  return config;
}

export function analyzeRepository({ repo, files = [], issues = [], comments = [], coverage = {} }) {
  const instructionFiles = [];
  const configs = [];
  const findings = [];

  for (const file of files) {
    const kind = classifyPath(file.path);
    if (kind === 'instructions') {
      const result = analyzeMarkdown(file.text, { visibleZone: 'voice', location: file.path, url: repo?.url ? `${repo.url}/blob/${repo.defaultBranch}/${file.path}` : null });
      instructionFiles.push({ path: file.path, segments: result.segments, findings: result.findings, bytes: file.text.length });
      findings.push(...result.findings);
    } else if (kind === 'mcp-config' || kind === 'agent-settings') {
      configs.push(analyzeConfig(file));
    }
  }

  const discussions = new Map();
  const discussionFor = (number) => {
    if (!discussions.has(number)) discussions.set(number, { number, title: null, url: null, isPullRequest: false, author: null, segments: [], findings: [], comments: 0 });
    return discussions.get(number);
  };

  for (const issue of issues) {
    const entry = discussionFor(issue.number);
    Object.assign(entry, { title: issue.title, url: issue.url, isPullRequest: Boolean(issue.isPullRequest), author: issue.author || null });
    const location = `${issue.isPullRequest ? 'Pull request' : 'Issue'} #${issue.number}`;
    const result = analyzeMarkdown(`${issue.title || ''}\n\n${issue.body || ''}`, { visibleZone: 'untrusted', location, url: issue.url, owner: issue.author });
    entry.segments.push(...result.segments);
    entry.findings.push(...result.findings);
    findings.push(...result.findings);
  }

  for (const comment of comments) {
    const entry = discussionFor(comment.issueNumber);
    entry.comments += 1;
    const result = analyzeMarkdown(comment.body || '', { visibleZone: 'untrusted', location: `Comment on #${comment.issueNumber}`, url: comment.url, owner: comment.author });
    entry.findings.push(...result.findings);
    findings.push(...result.findings);
  }

  const servers = configs.flatMap((config) => config.servers.map((server) => ({ ...server, path: config.path })));
  if (servers.length) {
    findings.push({
      kind: 'repo-mcp-servers',
      severity: 'info',
      title: `The repository offers ${servers.length} MCP server${servers.length === 1 ? '' : 's'}`,
      detail: `Agents that open this repository may be offered: ${servers.map((server) => server.name).join(', ')}.`,
      location: [...new Set(servers.map((server) => server.path))].join(', '),
      remediation: 'Check that each server is one you expect contributors to run.'
    });
  }
  const hooks = configs.flatMap((config) => config.hooks.map((hook) => ({ ...hook, path: config.path })));
  if (hooks.length) {
    findings.push({
      kind: 'repo-agent-hooks',
      severity: 'medium',
      title: `The repository asks agents to run ${hooks.length} shell command${hooks.length === 1 ? '' : 's'} automatically`,
      detail: 'Agent hooks run without a prompt once the repository is trusted.',
      excerpt: hooks.map((hook) => `${hook.event}: ${hook.command}`).join('\n').slice(0, 600),
      location: [...new Set(hooks.map((hook) => hook.path))].join(', '),
      remediation: 'Review each hook command before trusting the repository.'
    });
  }

  const ordered = findings
    .map((finding, index) => ({ id: `f${index + 1}`, ...finding }))
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const discussionList = [...discussions.values()].sort((a, b) => b.number - a.number);

  return {
    kind: 'repository',
    version: 1,
    repo,
    analyzedAt: new Date().toISOString(),
    instructionFiles,
    discussions: discussionList,
    configs,
    findings: ordered,
    summary: {
      counts: Object.fromEntries(SEVERITIES.map((severity) => [severity, ordered.filter((finding) => finding.severity === severity).length])),
      instructionFiles: instructionFiles.length,
      discussions: discussionList.length,
      comments: comments.length
    },
    coverage
  };
}
