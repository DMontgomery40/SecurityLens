// Build a security ledger from normalized agent sessions: what left the
// machine, which secrets were touched, which risky commands ran, and which
// consequential actions followed untrusted content before the human spoke
// again.

import { analyzeText } from '../isp/detect.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// A ".key" file only counts when it appears as a path segment, so object
// property access such as record.key in a script does not match.
const SECRET_PATH =
  /(?:(?:^|[\s/'"=~:])(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?|\.envrc|id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)|\.aws\/credentials|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker\/config\.json|\.kube\/config|credentials\.json|secrets?\.(?:ya?ml|json|env|toml)|[\w.-]+\.(?:pem|p12|pfx))|\/[\w.-]+\.key)(?=$|[\s'"`;|&)])/i;
const SECRET_COMMAND = /(?:^|[\s;|&(])(?:printenv|env(?=\s*(?:$|[|;&>]))|export -p|security find-(?:generic|internet)-password|gh auth token|gcloud auth print-access-token|aws configure get)/;

const SECRET_VALUES = [
  ['Anthropic key', /\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{40,}/g],
  ['OpenAI key', /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{30,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g],
  ['AWS access key', /\b(?:AKIA|ASIA)(?![0-9A-Z]*EXAMPLE)[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g],
  ['Slack token', /\bxox[baprs]-\d+-[A-Za-z0-9-]{10,}/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['Stripe live key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g],
  ['Private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{64,}/g]
];

const NETWORK_COMMAND =
  /(?:^|[\s;|&(])(?:curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|telnet|ftp)\s|\bgit\s+push\b|\b(?:npm|pnpm|yarn)\s+publish\b|\b(?:netlify|vercel|wrangler|firebase|heroku|flyctl|fly)\s+(?:deploy|publish)\b|\bgh\s+(?:pr|issue|release|api|repo|gist)\b|\baws\s+\S|\bgcloud\s+\S|\baz\s+\S|\bdocker\s+push\b|\btwine\s+upload\b|\bcargo\s+publish\b/;

const RISKY_COMMANDS = [
  ['Deletes files recursively', /\brm\s+-[a-zA-Z]*(?:r[a-zA-Z]*f|f[a-zA-Z]*r)\b/],
  ['Force-pushes over remote history', /\bgit\s+push\b[^\n;|&]*\s(?:--force(?![-\w])|-f\b)/],
  ['Discards local changes', /\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f)/],
  ['Runs as root', /(?:^|[\s;|&(])sudo\s/],
  ['Opens permissions to everyone', /\bchmod\s+(?:-R\s+)?777\b/],
  ['Pipes a download into a shell', /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/],
  ['Skips commit hooks', /--no-verify\b/],
  ['Drops a database object', /\bdrop\s+(?:table|database|schema)\b/i],
  ['Writes a raw disk', /\bmkfs\b|\bdd\s+if=/],
  ['Deploys to production', /\b(?:deploy|publish)\b[^\n]*--prod(?:uction)?\b/]
];

// After untrusted content gives the agent orders, the next few consequential
// actions are flagged. An action that does what the content said is always
// flagged until the human speaks again.
const WINDOW_ACTIONS = 3;
const WINDOW_MS = 10 * 60 * 1000;

const SENSITIVE_WRITE = /(?:^|\/)(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|authorized_keys|crontab)$|\.github\/workflows\/|\/\.ssh\/|^\/etc\/|\.git\/hooks\//;
const WRITE_LIKE_TOOL = /(create|update|delete|remove|send|post|push|merge|write|publish|deploy|pay|transfer|comment|approve|close|invite|share|upload|execute|run|submit)/i;

export function redactSecret(value) {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

function riskyReason(command) {
  const found = RISKY_COMMANDS.find(([, pattern]) => pattern.test(command));
  return found ? found[0] : null;
}

function isOutside(path, cwd) {
  if (!path || !cwd || !path.startsWith('/')) return false;
  const root = cwd.endsWith('/') ? cwd : `${cwd}/`;
  return !path.startsWith(root) && path !== cwd;
}

function describe(event) {
  if (event.kind === 'write') return `write ${event.target}`;
  return event.target || event.tool;
}

function consequential(event, cwd) {
  if (event.kind === 'command') return Boolean(riskyReason(event.target) || NETWORK_COMMAND.test(event.target) || /\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\b|\bpip\s+install\b|\bbrew\s+install\b/.test(event.target));
  if (event.kind === 'write') return isOutside(event.target, cwd) || SENSITIVE_WRITE.test(event.target);
  if (event.kind === 'mcp') return WRITE_LIKE_TOOL.test(event.mcpTool || event.tool);
  return false;
}

function urlsIn(text) {
  return String(text || '').match(/https?:\/\/[^\s"'`<>)]+/g) || [];
}

// Did the agent do what the injected text said? Either the whole action
// appears in it, or the action targets a URL the injected text named.
function followsInjection(event, injectionText) {
  const target = describe(event);
  if (!target || !injectionText) return false;
  if (target.length >= 8 && injectionText.includes(target)) return true;
  return urlsIn(target).some((url) => injectionText.includes(url));
}

function analyzeSession(session) {
  const findings = [];
  const egress = [];
  const mcpCalls = [];
  const origins = new Map();
  let taint = null;
  const seenSecrets = new Set();
  const seenSecretFiles = new Set();
  const counts = { commands: 0, fetches: 0, reads: 0, writes: 0, mcp: 0, prompts: 0 };

  const add = (finding) => findings.push({ sessionId: session.sessionId, harness: session.harness, cwd: session.cwd, ...finding });

  function scanSecrets(text, where, t) {
    for (const [type, pattern] of SECRET_VALUES) {
      for (const match of String(text || '').matchAll(pattern)) {
        const key = `${type}:${match[0]}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);
        add({
          kind: 'secret-in-context',
          severity: 'high',
          t,
          secretType: type,
          title: `${type} passed through the model`,
          detail: `It appeared in ${where}, so it was sent to the model provider.`,
          excerpt: `${type}: ${redactSecret(match[0])}`
        });
      }
    }
  }

  for (const event of session.events) {
    if (event.callId) origins.set(event.callId, origins.get(event.callId) || event);

    switch (event.kind) {
      case 'prompt':
        counts.prompts += 1;
        taint = null;
        scanSecrets(event.text, 'a prompt', event.t);
        continue;
      case 'result': {
        scanSecrets(event.text, 'tool output', event.t);
        const origin = event.callId ? origins.get(event.callId) : null;
        const source = origin && origin.untrustedSource ? origin : null;
        if (!source) continue;
        const analysis = analyzeText(event.text || '');
        const injected = analysis.strength === 'strong' && !analysis.quoted;
        const sourceLabel = source.url || source.target || source.tool;
        if (!injected) continue;
        add({
          kind: 'injection-seen',
          severity: 'medium',
          t: event.t,
          source: sourceLabel,
          title: 'Untrusted content contained instructions for the agent',
          detail: `Text returned by ${source.tool} reads like instructions to the agent.`,
          excerpt: analysis.matches[0]?.excerpt || ''
        });
        taint = {
          source: sourceLabel,
          injectionText: `${taint?.injectionText || ''}\n${event.text}`,
          startedMs: Date.parse(event.t) || null,
          remaining: WINDOW_ACTIONS
        };
        continue;
      }
      default:
        break;
    }

    if (event.kind === 'command') counts.commands += 1;
    if (event.kind === 'fetch' || event.kind === 'search') counts.fetches += 1;
    if (event.kind === 'read') counts.reads += 1;
    if (event.kind === 'write') counts.writes += 1;
    if (event.kind === 'mcp') {
      counts.mcp += 1;
      mcpCalls.push(event);
    }

    if (event.kind === 'fetch' || event.kind === 'search' || event.kind === 'mcp' || (event.kind === 'command' && NETWORK_COMMAND.test(event.target))) {
      egress.push({ sessionId: session.sessionId, harness: session.harness, t: event.t, kind: event.kind, target: event.target });
    }

    if (
      (event.kind === 'read' || event.kind === 'command') &&
      !seenSecretFiles.has(event.target) &&
      (SECRET_PATH.test(event.target) || (event.kind === 'command' && SECRET_COMMAND.test(event.target)))
    ) {
      seenSecretFiles.add(event.target);
      add({ kind: 'secret-file', severity: 'medium', t: event.t, action: event.target, title: 'Read a secret file', detail: 'Its contents went into the model context.' });
    }
    if (event.kind === 'command') scanSecrets(event.target, 'a command', event.t);

    const risky = event.kind === 'command' ? riskyReason(event.target) : null;
    if (risky) {
      add({ kind: 'risky-command', severity: /Pipes a download|Force-pushes/.test(risky) ? 'high' : 'medium', t: event.t, action: event.target, title: risky });
    }

    if (taint && consequential(event, session.cwd)) {
      const followed = followsInjection(event, taint.injectionText);
      const elapsed = taint.startedMs && Date.parse(event.t) ? Date.parse(event.t) - taint.startedMs : 0;
      const inWindow = taint.remaining > 0 && elapsed <= WINDOW_MS;
      if (!followed && !inWindow) continue;
      if (!followed) taint.remaining -= 1;
      add({
        kind: followed ? 'action-after-injection' : 'action-after-untrusted',
        severity: followed ? 'critical' : 'high',
        t: event.t,
        action: describe(event),
        source: taint.source,
        title: followed ? 'The agent did what untrusted content told it to' : 'Consequential action after reading untrusted content',
        detail: followed
          ? `Content from ${taint.source} told the agent to do this, and it did, before you said anything else.`
          : `The agent read ${taint.source} and then took this action before you said anything else.`,
        excerpt: followed ? taint.injectionText.trim().slice(0, 400) : ''
      });
    }
  }

  return { findings, egress, mcpCalls, counts };
}

export function buildLedger(sessions) {
  const valid = sessions.filter(Boolean);
  const findings = [];
  const egress = [];
  const servers = new Map();
  const summaries = [];
  const harnesses = {};
  const totals = { commands: 0, fetches: 0, reads: 0, writes: 0, mcp: 0, prompts: 0 };
  let from = null;
  let to = null;

  for (const session of valid) {
    const result = analyzeSession(session);
    findings.push(...result.findings);
    egress.push(...result.egress);
    harnesses[session.harness] = (harnesses[session.harness] || 0) + 1;
    for (const [key, value] of Object.entries(result.counts)) totals[key] += value;
    for (const call of result.mcpCalls) {
      const entry = servers.get(call.server) || { server: call.server, calls: 0, tools: new Set() };
      entry.calls += 1;
      entry.tools.add(call.mcpTool);
      servers.set(call.server, entry);
    }
    const times = session.events.map((event) => event.t).filter(Boolean).sort();
    const start = session.startedAt || times[0] || null;
    const end = times[times.length - 1] || start;
    if (start && (!from || start < from)) from = start;
    if (end && (!to || end > to)) to = end;
    summaries.push({
      sessionId: session.sessionId,
      harness: session.harness,
      cwd: session.cwd,
      project: session.cwd ? session.cwd.split('/').filter(Boolean).pop() : null,
      file: session.file,
      startedAt: start,
      endedAt: end,
      counts: result.counts,
      findings: result.findings.length,
      worst: result.findings.reduce((best, finding) => (SEVERITIES.indexOf(finding.severity) < SEVERITIES.indexOf(best) ? finding.severity : best), 'info')
    });
  }

  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || String(b.t).localeCompare(String(a.t)));
  summaries.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
  egress.sort((a, b) => String(b.t).localeCompare(String(a.t)));

  return {
    summary: {
      sessions: valid.length,
      harnesses,
      ...totals,
      from,
      to,
      counts: Object.fromEntries(SEVERITIES.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length]))
    },
    sessions: summaries,
    findings: findings.map((finding, index) => ({ id: `rv${index + 1}`, ...finding })),
    egress,
    mcpServers: [...servers.values()].map((entry) => ({ server: entry.server, calls: entry.calls, tools: [...entry.tools].sort() })).sort((a, b) => b.calls - a.calls)
  };
}
