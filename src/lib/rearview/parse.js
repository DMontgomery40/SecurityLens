// Normalize agent session transcripts from Claude Code and Codex into one
// event stream: prompts from the human, the actions the agent took, and the
// results that came back. Runs in a browser worker; nothing is uploaded.

const RESULT_TEXT_LIMIT = 20000;

function parseLines(text) {
  const objects = [];
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    try {
      objects.push(JSON.parse(line));
    } catch {
      // Transcripts can end mid-write; skip lines that do not parse.
    }
  }
  return objects;
}

function detectFormat(objects) {
  if (objects.some((object) => object.type === 'session_meta' || (object.type === 'response_item' && object.payload))) return 'codex';
  if (objects.some((object) => (object.type === 'user' || object.type === 'assistant') && object.message && object.sessionId)) return 'claude-code';
  return null;
}

function mcpParts(name) {
  const parts = String(name).split('__');
  if (parts[0] !== 'mcp' || parts.length < 3) return null;
  return { server: parts[1], tool: parts.slice(2).join('__') };
}

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((item) => (typeof item === 'string' ? item : item?.text || item?.content || ''))
      .filter((part) => typeof part === 'string')
      .join('\n');
  }
  return '';
}

const HARNESS_TEXT = /^\s*(<(system-reminder|environment_context|user_instructions|app-context|skills_instructions|recommended_plugins|command-|local-command|permissions)|# AGENTS\.md instructions|Caveat: The messages below)/;

function isHumanText(text) {
  return Boolean(text && text.trim()) && !HARNESS_TEXT.test(text);
}

function patchPaths(patch) {
  return [...String(patch || '').matchAll(/\*\*\* (?:Update|Add|Delete) File: (.+)/g)].map((match) => match[1].trim());
}

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

function claudeToolEvent(item) {
  const name = item.name || '';
  const input = item.input || {};
  const base = { tool: name, callId: item.id || null };
  const mcp = mcpParts(name);

  if (mcp) {
    const browsing = /chrome|browser|playwright|puppeteer|fetch|web/i.test(mcp.server) || /(get_page_text|read_page|navigate|fetch|scrape)/i.test(mcp.tool);
    return { ...base, kind: 'mcp', server: mcp.server, mcpTool: mcp.tool, target: name, url: typeof input.url === 'string' ? input.url : null, untrustedSource: true, browsing };
  }

  switch (name) {
    case 'Bash':
      return { ...base, kind: 'command', target: String(input.command || '') };
    case 'Read':
    case 'NotebookRead':
      return { ...base, kind: 'read', target: String(input.file_path || input.notebook_path || '') };
    case 'Write':
    case 'Edit':
    case 'MultiEdit':
    case 'NotebookEdit':
      return { ...base, kind: 'write', target: String(input.file_path || input.notebook_path || '') };
    case 'WebFetch':
      return { ...base, kind: 'fetch', target: String(input.url || ''), untrustedSource: true };
    case 'WebSearch':
      return { ...base, kind: 'search', target: String(input.query || ''), untrustedSource: true };
    default:
      return null;
  }
}

function parseClaude(objects, filename) {
  const events = [];
  let sessionId = null;
  let cwd = null;
  let startedAt = null;

  for (const object of objects) {
    if (object.type !== 'user' && object.type !== 'assistant') continue;
    sessionId = sessionId || object.sessionId || null;
    cwd = cwd || object.cwd || null;
    startedAt = startedAt || object.timestamp || null;
    const t = object.timestamp || null;
    const content = object.message?.content;

    if (object.type === 'user') {
      if (typeof content === 'string') {
        if (!object.isMeta && isHumanText(content)) events.push({ t, kind: 'prompt', text: content.slice(0, 2000) });
        continue;
      }
      for (const item of Array.isArray(content) ? content : []) {
        if (item?.type === 'tool_result') {
          events.push({ t, kind: 'result', callId: item.tool_use_id || null, text: textOf(item.content).slice(0, RESULT_TEXT_LIMIT), isError: Boolean(item.is_error) });
        } else if (item?.type === 'text' && !object.isMeta && isHumanText(item.text)) {
          events.push({ t, kind: 'prompt', text: item.text.slice(0, 2000) });
        }
      }
      continue;
    }

    for (const item of Array.isArray(content) ? content : []) {
      if (item?.type !== 'tool_use') continue;
      const event = claudeToolEvent(item);
      if (event) events.push({ t, ...event });
    }
  }

  return { harness: 'claude-code', sessionId: sessionId || filename, cwd, startedAt, file: filename, events };
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

// Find the argument text of a call that starts at `open` (the index of "(").
function callArguments(source, open) {
  let depth = 0;
  let quote = null;
  for (let index = open; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (char === '\\') index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === '`') quote = char;
    else if (char === '(' || char === '{' || char === '[') depth += 1;
    else if (char === ')' || char === '}' || char === ']') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  return source.slice(open + 1);
}

function stringField(args, field) {
  const match = args.match(new RegExp(`["']?${field}["']?\\s*:\\s*("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\`(?:[^\`\\\\]|\\\\.)*\`)`));
  if (!match) return null;
  const literal = match[1];
  if (literal.startsWith('"')) {
    try {
      return JSON.parse(literal);
    } catch {
      return literal.slice(1, -1);
    }
  }
  return literal.slice(1, -1).replace(/\\n/g, '\n').replace(/\\(['`\\])/g, '$1');
}

function commandFromArgs(args) {
  if (Array.isArray(args?.command)) {
    const parts = args.command.map(String);
    const shellIndex = parts.findIndex((part) => part === '-lc' || part === '-c');
    return shellIndex >= 0 && parts[shellIndex + 1] ? parts[shellIndex + 1] : parts.join(' ');
  }
  if (typeof args?.command === 'string') return args.command;
  if (typeof args?.cmd === 'string') return args.cmd;
  return null;
}

const URL_PATTERN = /https?:\/\/[^\s"'`\\)\]}>,]+/g;

function codexCellEvents(source, callId) {
  const events = [];
  for (const match of String(source || '').matchAll(/\btools\.([A-Za-z_][\w]*)\s*\(/g)) {
    const name = match[1];
    const args = callArguments(source, match.index + match[0].length - 1);
    const mcp = mcpParts(name);

    if (name === 'exec_command' || name === 'shell' || name === 'local_shell') {
      const cmd = stringField(args, 'cmd') ?? stringField(args, 'command');
      if (cmd) events.push({ kind: 'command', tool: name, target: cmd, callId });
    } else if (/^web(__|_)?(run|search|open|fetch)/.test(name) || name === 'web__run') {
      const url = (args.match(URL_PATTERN) || [])[0];
      if (url) events.push({ kind: 'fetch', tool: name, target: url, callId, untrustedSource: true });
      else events.push({ kind: 'search', tool: name, target: stringField(args, 'q') || stringField(args, 'query') || 'web search', callId, untrustedSource: true });
    } else if (name === 'apply_patch') {
      for (const path of patchPaths(args.replace(/\\n/g, '\n'))) events.push({ kind: 'write', tool: name, target: path, callId });
    } else if (mcp) {
      events.push({ kind: 'mcp', tool: name, server: mcp.server, mcpTool: mcp.tool, target: name, callId, untrustedSource: true });
    }
  }
  return events;
}

function parseCodex(objects, filename) {
  const events = [];
  let sessionId = null;
  let cwd = null;
  let startedAt = null;

  for (const object of objects) {
    const payload = object.payload || {};
    const t = object.timestamp || null;

    if (object.type === 'session_meta') {
      sessionId = sessionId || payload.id || payload.session_id || null;
      cwd = cwd || payload.cwd || null;
      startedAt = startedAt || payload.timestamp || object.timestamp || null;
      continue;
    }
    if (object.type === 'turn_context') {
      cwd = cwd || payload.cwd || null;
      continue;
    }
    if (object.type !== 'response_item') continue;
    startedAt = startedAt || t;

    switch (payload.type) {
      case 'message': {
        if (payload.role !== 'user') break;
        const text = textOf(payload.content);
        if (isHumanText(text)) events.push({ t, kind: 'prompt', text: text.slice(0, 2000) });
        break;
      }
      case 'custom_tool_call': {
        if (payload.name === 'exec') {
          for (const event of codexCellEvents(payload.input, payload.call_id || null)) events.push({ t, ...event });
        } else if (payload.name === 'apply_patch') {
          for (const path of patchPaths(payload.input)) events.push({ t, kind: 'write', tool: 'apply_patch', target: path, callId: payload.call_id || null });
        }
        break;
      }
      case 'function_call': {
        let args = {};
        try {
          args = JSON.parse(payload.arguments || '{}');
        } catch {
          args = {};
        }
        const name = payload.name || '';
        const mcp = mcpParts(name);
        if (['shell', 'exec_command', 'local_shell', 'container.exec'].includes(name)) {
          const cmd = commandFromArgs(args);
          if (cmd) events.push({ t, kind: 'command', tool: name, target: cmd, callId: payload.call_id || null });
        } else if (name === 'apply_patch') {
          for (const path of patchPaths(args.input)) events.push({ t, kind: 'write', tool: name, target: path, callId: payload.call_id || null });
        } else if (mcp) {
          events.push({ t, kind: 'mcp', tool: name, server: mcp.server, mcpTool: mcp.tool, target: name, callId: payload.call_id || null, untrustedSource: true });
        }
        break;
      }
      case 'web_search_call': {
        const query = payload.action?.query || payload.query || 'web search';
        events.push({ t, kind: 'search', tool: 'web_search', target: String(query), callId: payload.id || null, untrustedSource: true });
        break;
      }
      case 'function_call_output':
      case 'custom_tool_call_output': {
        const output = typeof payload.output === 'string' ? payload.output : textOf(payload.output);
        events.push({ t, kind: 'result', callId: payload.call_id || null, text: String(output || '').slice(0, RESULT_TEXT_LIMIT) });
        break;
      }
      default:
        break;
    }
  }

  return { harness: 'codex', sessionId: sessionId || filename, cwd, startedAt, file: filename, events };
}

export function parseTranscript(text, { filename = 'session.jsonl' } = {}) {
  const objects = parseLines(text);
  const format = detectFormat(objects);
  if (format === 'codex') return parseCodex(objects, filename);
  if (format === 'claude-code') return parseClaude(objects, filename);
  return null;
}
