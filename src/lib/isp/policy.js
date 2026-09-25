// Instruction Security Policy: parsing, serialization, and source precedence.
// Reference implementation of docs/spec/instruction-security-policy.md.

import { parse as parseSelector } from 'css-what';

export const POLICY_HEADER = 'Instruction-Security-Policy';
export const WELL_KNOWN_PATH = '/.well-known/instruction-security-policy';
export const ELEMENT_ATTRIBUTE = 'data-isp';

const DIRECTIVE_NAMES = ['default', 'voice', 'untrusted', 'tools', 'instructions', 'report-to'];
const TRUST_DIRECTIVES = new Set(['default', 'voice']);
const COMBINATOR_TYPES = new Set(['child', 'descendant', 'adjacent', 'sibling', 'parent', 'column-combinator']);
const DIRECTIVE_AS_SELECTOR = new RegExp(`^(${DIRECTIVE_NAMES.join('|')})\\s`, 'i');

export function emptyDirectives() {
  return {
    default: 'voice',
    voice: [],
    untrusted: [],
    tools: null,
    instructions: null,
    reportTo: null
  };
}

// Split on a delimiter that sits outside quotes, parentheses, and brackets.
function splitTopLevel(input, delimiter) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let current = '';

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];

    if (quote) {
      current += char;
      if (char === '\\' && index + 1 < input.length) {
        current += input[index + 1];
        index += 1;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }

    if (char === '(' || char === '[') depth += 1;
    if ((char === ')' || char === ']') && depth > 0) depth -= 1;

    if (char === delimiter && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }

    current += char;
  }

  parts.push(current);
  return parts;
}

function subjectCompound(tokens) {
  let start = 0;
  tokens.forEach((token, index) => {
    if (COMBINATOR_TYPES.has(token.type)) start = index + 1;
  });
  return tokens.slice(start);
}

function containsSpoofableToken(tokens) {
  return tokens.some((token) => {
    if (token.type === 'attribute') return token.name !== 'id';
    if (token.type === 'pseudo' && Array.isArray(token.data)) {
      return token.data.some((inner) => containsSpoofableToken(inner));
    }
    return false;
  });
}

function hasIdToken(tokens) {
  return tokens.some((token) => token.type === 'attribute' && token.name === 'id');
}

// A voice selector is spoofable when user content could produce a matching
// element: its subject relies on classes or attributes and has no id.
export function isSpoofableSelector(selector) {
  try {
    return parseSelector(selector).some((tokens) => {
      const subject = subjectCompound(tokens);
      return containsSpoofableToken(subject) && !hasIdToken(subject);
    });
  } catch {
    return false;
  }
}

const CSS_IDENT = /^-?(?:[_a-zA-Z -￿]|--)[_a-zA-Z0-9 -￿-]*$/;

function tokensAreStrict(tokens, rawHasEscape) {
  if (tokens.length === 0) return false;
  if (COMBINATOR_TYPES.has(tokens[0].type) || COMBINATOR_TYPES.has(tokens[tokens.length - 1].type)) return false;

  return tokens.every((token) => {
    const isClassOrId =
      token.type === 'attribute' &&
      ((token.name === 'class' && token.action === 'element') || (token.name === 'id' && token.action === 'equals'));
    if (isClassOrId && !rawHasEscape && !CSS_IDENT.test(token.value)) return false;
    if (token.type === 'pseudo' && Array.isArray(token.data)) {
      return token.data.every((inner) => inner.length > 0 && tokensAreStrict(inner, rawHasEscape));
    }
    return true;
  });
}

// css-what accepts some malformed input, such as "..a" or "p >", so apply
// the stricter rules a browser would.
export function isValidSelector(selector) {
  try {
    const parsed = parseSelector(selector);
    const rawHasEscape = selector.includes('\\');
    return parsed.length > 0 && parsed.every((tokens) => tokensAreStrict(tokens, rawHasEscape));
  } catch {
    return false;
  }
}

function parseSelectorList(value, directive, errors) {
  const selectors = [];
  let combined = false;

  for (const rawSelector of splitTopLevel(value, ',')) {
    const selector = rawSelector.trim();
    if (!selector) continue;

    if (DIRECTIVE_AS_SELECTOR.test(selector)) {
      combined = true;
      errors.push({
        code: 'combined-policies',
        directive,
        message: `"${selector}" looks like a directive inside a selector list. Two policies were probably combined into one header value.`
      });
      continue;
    }

    if (isValidSelector(selector)) {
      selectors.push(selector);
    } else {
      errors.push({
        code: 'invalid-selector',
        directive,
        message: `"${selector}" is not a valid CSS selector.`
      });
    }
  }

  return { selectors, combined };
}

function normalizeOrigin(source) {
  const wildcard = source.match(/^(https?):\/\/\*\.([^/:]+)(:\d+)?\/?$/i);
  if (wildcard) {
    return `${wildcard[1].toLowerCase()}://*.${wildcard[2].toLowerCase()}${wildcard[3] || ''}`;
  }

  try {
    const url = new URL(source);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    if ((url.pathname && url.pathname !== '/') || url.search || url.hash) return null;
    if (!/^[a-z]+:\/\//i.test(source)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function parseTools(value, errors, warnings) {
  const tokens = value.split(/\s+/).filter(Boolean);
  const sources = [];

  for (const token of tokens) {
    const lower = token.toLowerCase();
    if (lower === "'self'" || lower === "'none'") {
      if (!sources.includes(lower)) sources.push(lower);
      continue;
    }

    const origin = normalizeOrigin(token);
    if (origin) {
      if (!sources.includes(origin)) sources.push(origin);
    } else {
      errors.push({
        code: 'invalid-tool-source',
        directive: 'tools',
        message: `"${token}" is not 'self', 'none', or an origin such as https://example.com.`
      });
    }
  }

  if (sources.includes("'none'") && sources.length > 1) {
    warnings.push({
      code: 'tools-none-combined',
      directive: 'tools',
      message: "'none' cannot be combined with other sources, so no tools are allowed."
    });
    return ["'none'"];
  }

  return sources;
}

function parseAbsoluteHttps(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && /^https:\/\//i.test(value) ? url.href : null;
  } catch {
    return null;
  }
}

function parseInstructionsUrl(value) {
  try {
    const url = new URL(value, 'https://placeholder.invalid/');
    return ['http:', 'https:'].includes(url.protocol) ? value : null;
  } catch {
    return null;
  }
}

export function parsePolicy(text) {
  const raw = typeof text === 'string' ? text : '';
  const directives = emptyDirectives();
  const errors = [];
  const warnings = [];
  const seen = new Map();
  let failClosed = false;

  const pieces = splitTopLevel(raw, ';')
    .map((piece) => piece.trim())
    .filter(Boolean);

  if (pieces.length === 0) {
    warnings.push({ code: 'empty-policy', directive: null, message: 'The policy is empty.' });
  }

  for (const piece of pieces) {
    const match = piece.match(/^([A-Za-z-]+)(?:\s+([\s\S]*))?$/);
    if (!match) {
      errors.push({ code: 'malformed-directive', directive: null, message: `"${piece}" is not a directive.` });
      continue;
    }

    const name = match[1].toLowerCase();
    const value = (match[2] || '').trim();

    if (!DIRECTIVE_NAMES.includes(name)) {
      warnings.push({ code: 'unknown-directive', directive: name, message: `Unknown directive "${name}" was ignored.` });
      continue;
    }

    const count = (seen.get(name) || 0) + 1;
    seen.set(name, count);

    if (count > 1 && name !== 'untrusted') {
      errors.push({
        code: 'duplicate-directive',
        directive: name,
        message: `"${name}" appears more than once.`
      });
      if (TRUST_DIRECTIVES.has(name)) failClosed = true;
      continue;
    }

    switch (name) {
      case 'default': {
        const zone = value.toLowerCase();
        if (zone === 'voice' || zone === 'untrusted') {
          directives.default = zone;
        } else {
          failClosed = true;
          errors.push({
            code: 'invalid-default',
            directive: 'default',
            message: `default must be "voice" or "untrusted", not "${value}".`
          });
        }
        break;
      }
      case 'voice':
      case 'untrusted': {
        const { selectors, combined } = parseSelectorList(value, name, errors);
        if (combined) failClosed = true;
        if (selectors.length === 0 && !combined) {
          errors.push({ code: 'empty-selector-list', directive: name, message: `"${name}" has no valid selectors.` });
          if (name === 'voice') failClosed = true;
        }
        if (name === 'voice') {
          directives.voice = selectors;
          for (const selector of selectors) {
            if (isSpoofableSelector(selector)) {
              warnings.push({
                code: 'spoofable-voice-selector',
                directive: 'voice',
                selector,
                message: `"${selector}" relies on classes or attributes that user content could also carry. Prefer an id or a structural selector.`
              });
            }
          }
        } else {
          for (const selector of selectors) {
            if (!directives.untrusted.includes(selector)) directives.untrusted.push(selector);
          }
        }
        break;
      }
      case 'tools':
        directives.tools = parseTools(value, errors, warnings);
        break;
      case 'instructions': {
        const url = parseInstructionsUrl(value);
        if (url) {
          directives.instructions = url;
        } else {
          errors.push({ code: 'invalid-instructions', directive: 'instructions', message: `"${value}" is not a valid URL.` });
        }
        break;
      }
      case 'report-to': {
        const url = parseAbsoluteHttps(value);
        if (url) {
          directives.reportTo = url;
        } else {
          errors.push({
            code: 'invalid-report-to',
            directive: 'report-to',
            message: `report-to must be an absolute https URL, not "${value}".`
          });
        }
        break;
      }
      default:
        break;
    }
  }

  if (failClosed) {
    directives.voice = [];
    directives.default = 'voice';
  }

  return { raw, directives, errors, warnings, failedClosed: failClosed };
}

export function serializePolicy(directives) {
  const parts = [`default ${directives.default === 'untrusted' ? 'untrusted' : 'voice'}`];
  if (directives.voice?.length) parts.push(`voice ${directives.voice.join(', ')}`);
  if (directives.untrusted?.length) parts.push(`untrusted ${directives.untrusted.join(', ')}`);
  if (Array.isArray(directives.tools) && directives.tools.length) parts.push(`tools ${directives.tools.join(' ')}`);
  if (directives.instructions) parts.push(`instructions ${directives.instructions}`);
  if (directives.reportTo) parts.push(`report-to ${directives.reportTo}`);
  return parts.join('; ');
}

const SOURCE_ORDER = [
  ['header', 'header'],
  ['meta', 'meta'],
  ['wellKnown', 'well-known']
];

function normalizeSourceValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(', ') : null;
  return typeof value === 'string' ? value : null;
}

// Combine the header, first head meta element, and well-known file into the
// effective policy. The first present source is authoritative; untrusted
// selectors from every source are combined because restriction is always safe.
export function resolveEffectivePolicy(sources = {}) {
  const parsedSources = SOURCE_ORDER.map(([key, label]) => {
    const raw = normalizeSourceValue(sources[key]);
    return raw === null ? null : { source: label, raw, parsed: parsePolicy(raw) };
  }).filter(Boolean);

  if (parsedSources.length === 0) {
    return {
      present: false,
      source: null,
      directives: emptyDirectives(),
      failedClosed: false,
      errors: [],
      warnings: [],
      sources: []
    };
  }

  const [authoritative, ...others] = parsedSources;
  const directives = {
    ...authoritative.parsed.directives,
    voice: [...authoritative.parsed.directives.voice],
    untrusted: [...authoritative.parsed.directives.untrusted]
  };
  const errors = authoritative.parsed.errors.map((item) => ({ ...item, source: authoritative.source }));
  const warnings = authoritative.parsed.warnings.map((item) => ({ ...item, source: authoritative.source }));

  for (const other of others) {
    for (const selector of other.parsed.directives.untrusted) {
      if (!directives.untrusted.includes(selector)) directives.untrusted.push(selector);
    }
    errors.push(...other.parsed.errors.map((item) => ({ ...item, source: other.source })));
    warnings.push(...other.parsed.warnings.map((item) => ({ ...item, source: other.source })));

    const grantsIgnored = other.parsed.directives.voice.length > 0 || /(^|;)\s*default\s/i.test(other.raw);
    if (grantsIgnored) {
      warnings.push({
        code: 'ignored-non-authoritative',
        directive: 'voice',
        source: other.source,
        message: `The ${other.source} policy's voice and default directives were ignored because the ${authoritative.source} policy is authoritative.`
      });
    }
  }

  return {
    present: true,
    source: authoritative.source,
    directives,
    failedClosed: authoritative.parsed.failedClosed,
    errors,
    warnings,
    sources: parsedSources
  };
}
