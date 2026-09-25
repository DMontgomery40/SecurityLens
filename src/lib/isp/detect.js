// Detection of instruction-shaped text and invisible Unicode payloads.
// Runs in the browser and in Node. Rules are deliberately narrow: a phrase
// only counts when it reads as an order addressed to a model or agent.

const STRONG = 3;
const MEDIUM = 2;
const WEAK = 1;

const NEGATION_BEFORE = /\b(never|don't|do not|dont|avoid|not|stop|shouldn't|should not|mustn't|must not|without)\b[\w\s,]{0,12}$/i;

export const RULES = [
  {
    id: 'instruction-override',
    label: 'Tries to override earlier instructions',
    weight: STRONG,
    patterns: [
      /\b(ignore|disregard|forget|override|bypass)\b[\s\S]{0,25}?\b(all|any|every|the|your|previous|prior|above|earlier|preceding|initial|original|system)\b[\s\S]{0,25}?\b(instructions?|prompts?|rules|directives?|guidelines|guidance|constraints)\b/i
    ]
  },
  {
    id: 'role-marker',
    label: 'Contains chat-template or fake system markers',
    weight: STRONG,
    patterns: [
      /<\|(im_start|im_end|system|user|assistant|endoftext)\|>/i,
      /\[\/?INST\]/,
      /<<\/?SYS>>/,
      /<\/?(system|system_prompt|system-prompt)>/i,
      /\b(BEGIN|END) (SYSTEM|HIDDEN|DEVELOPER) (PROMPT|INSTRUCTIONS?|MESSAGE)\b/i
    ]
  },
  {
    id: 'persona-hijack',
    label: 'Tries to give the agent a new role or task',
    weight: STRONG,
    patterns: [
      /\b(you are now|you're now|from now on,? you (will|are|must|should|shall))\b/i,
      /\bact as (an? )?(unfiltered|unrestricted|jailbroken|uncensored)\b/i,
      /\b(developer|DAN|god) mode (enabled|activated|on)\b/i,
      /\b(new|updated|revised|real|true|actual) (instructions?|task|objective|goal|directive|orders)\s*:/i,
      /\byour (new|real|true|actual) (task|goal|objective|instructions?|purpose) (is|are)\b/i
    ]
  },
  {
    id: 'secrecy',
    label: 'Asks the agent to hide something from its user',
    weight: STRONG,
    patterns: [
      /\b(do not|don't|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|disclos(e|ing)|notify(ing)?|alert(ing)?|let(ting)?)\s+(the\s+)?(user|human|operator|owner)s?\b/i,
      /\bkeep (this|these|it) (hidden|secret|confidential) from (the\s+)?(user|human|operator)s?\b/i
    ]
  },
  {
    id: 'exfiltration',
    label: 'Asks the agent to send secrets or conversation data somewhere',
    weight: STRONG,
    negatable: true,
    patterns: [
      /\b(send|post|upload|forward|email|e-mail|transmit|leak|exfiltrate|append|paste)\b[\s\S]{0,60}?\b(api[ _-]?keys?|access tokens?|auth tokens?|credentials?|passwords?|secrets?|cookies?|session (ids?|tokens?)|env(ironment)? (vars?|variables?)|\.env\b|ssh keys?|private keys?|conversation|chat history|system prompt)\b/i,
      /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*(\{|%7B|\$\{)[^)]*\)/i
    ]
  },
  {
    id: 'prompt-leak',
    label: 'Asks the agent to reveal its instructions',
    weight: MEDIUM,
    patterns: [
      /\b(print|reveal|output|repeat|show|display|disclose|tell me)\b[\s\S]{0,20}?\b(your|the) (system prompt|initial prompt|hidden (prompt|instructions)|instructions above|original instructions|developer message)\b/i
    ]
  },
  {
    id: 'output-steering',
    label: 'Tries to steer what the agent says or decides',
    weight: MEDIUM,
    patterns: [
      /\b(when|if|while) (summari[sz]|describ|review|evaluat|rank|rat|analy[sz])\w*\s+(this|the) (page|article|document|site|website|post|repo|repository|product|candidate|resume|cv|application|listing|review)\b/i,
      /\bin your (summary|response|answer|review|evaluation|output),? (say|state|mention|include|claim|write|note)\b/i,
      /(?:^|[.!?:;,]\s*)(?:please\s+)?(?:always\s+)?(recommend|endorse|rank|rate|score|promote|praise) (this|our|the following) (product|candidate|applicant|company|service|app|listing|plugin|extension|package|library|tool|vendor|site|website|course|book|hotel|restaurant|model|kettle|brand)\b/i,
      /\b(recommend|praise|promote|endorse|claim|say|state)\b[\s\S]{0,60}?\bin your (summary|response|answer|review|output|report)\b/i,
      /\b(give|rate) (this|the) (candidate|applicant|product|ad|review|app) (a )?(\d+|five|ten|perfect|highest|top)\b/i,
      /\b(approve|merge|accept) (this|the) (pull request|transaction|payment|application|candidate|ad)\b/i
    ]
  },
  {
    id: 'tool-coercion',
    label: 'Tells the agent to run commands or call tools',
    weight: MEDIUM,
    patterns: [
      /\b(run|execute|eval)\s+(the\s+following|this|these)\s+(command|commands|code|script|snippet)\b/i,
      /\b(curl|wget)\s+[^\n|]{0,200}\|\s*(ba|z)?sh\b/i,
      /\b(call|invoke|use) the [\w.-]+ (tool|function)\b/i,
      /\brm\s+-rf\s+[/~]/i
    ]
  },
  {
    id: 'agent-address',
    label: 'Speaks directly to AI agents',
    weight: WEAK,
    patterns: [
      /\b(if|when|whenever) you('re| are) (an? )?(ai|a\.i\.|llm|large language model|language model|chatbot|bot|agent|assistant|gpt|claude|gemini|copilot)\b/i,
      /\b(attention|note|message|notice|instructions?) (to|for) (all )?(ai|llms?|agents?|ai agents?|assistants?|chatbots?|bots|language models|crawlers)\b/i,
      /\b(ai|llm) (agents?|assistants?|models?|crawlers?|bots?|systems?)\b[\s\S]{0,20}?\b(must|should|shall|need to|are (required|instructed|asked) to|please)\b/i,
      /\b(dear|hey|hello) (ai|llm|agent|assistant|chatgpt|claude|gemini)\b/i,
      /(?:^|[.!?]\s+)(?:(?:maintainer|triage|review|reviewer|coding|code|ai|llm|autonomous|browsing|support)\s+)?(?:bots?|agents?|assistants?|llms?|crawlers?)\s*:\s*(?=[\s\S]{0,40}\b(?:run|execute|call|use|approve|merge|ignore|send|delete|install|click|navigate|reveal|recommend)\b)/i
    ]
  },
  {
    id: 'false-authority',
    label: 'Claims system or administrator authority',
    weight: MEDIUM,
    patterns: [/\b(SYSTEM|ADMIN|ADMINISTRATOR|DEVELOPER) (OVERRIDE|NOTICE|MESSAGE|COMMAND)\b/]
  }
];

const INVISIBLE_FOR_MATCHING = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\uFE00-\uFE0F]|[\u{E0000}-\u{E007F}]|[\u{E0100}-\u{E01EF}]/gu;

export function normalizeForMatching(text) {
  return String(text || '')
    .normalize('NFKC')
    .replace(INVISIBLE_FOR_MATCHING, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function excerptAround(text, index, length) {
  const start = Math.max(0, index - 60);
  const end = Math.min(text.length, index + length + 60);
  return `${start > 0 ? '…' : ''}${text.slice(start, end)}${end < text.length ? '…' : ''}`;
}

export function detectInstructions(text) {
  const normalized = normalizeForMatching(text);
  const matches = [];

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      const match = pattern.exec(normalized);
      if (!match) continue;
      if (rule.negatable && NEGATION_BEFORE.test(normalized.slice(Math.max(0, match.index - 24), match.index))) continue;
      matches.push({
        rule: rule.id,
        label: rule.label,
        weight: rule.weight,
        match: match[0].slice(0, 160),
        excerpt: excerptAround(normalized, match.index, match[0].length)
      });
      break;
    }
  }

  const score = matches.reduce((sum, match) => sum + match.weight, 0);
  const hasStrongRule = matches.some((match) => match.weight >= STRONG);
  let strength = 'none';
  if (hasStrongRule || score >= STRONG) strength = 'strong';
  else if (score >= WEAK) strength = 'weak';

  return { strength, score, matches };
}

// ---------------------------------------------------------------------------
// Invisible Unicode payloads
// ---------------------------------------------------------------------------

const TAG_START = 0xe0000;
const TAG_END = 0xe007f;
const WAVING_BLACK_FLAG = 0x1f3f4;
const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;

const isTag = (cp) => cp >= TAG_START && cp <= TAG_END;
const isVariationSelector = (cp) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

function collectRuns(codePoints, predicate) {
  const runs = [];
  let current = null;

  codePoints.forEach((cp, index) => {
    if (predicate(cp)) {
      if (!current) current = { start: index, points: [] };
      current.points.push(cp);
    } else if (current) {
      runs.push(current);
      current = null;
    }
  });

  if (current) runs.push(current);
  return runs;
}

function printableRatio(value) {
  if (!value.length) return 0;
  const printable = [...value].filter((char) => /[\p{L}\p{N}\p{P}\p{Zs}\n\t]/u.test(char)).length;
  return printable / [...value].length;
}

function isSubdivisionFlag(codePoints, run) {
  if (run.start === 0 || codePoints[run.start - 1] !== WAVING_BLACK_FLAG) return false;
  const letters = run.points.slice(0, -1);
  const last = run.points[run.points.length - 1];
  return (
    last === TAG_END &&
    letters.length >= 2 &&
    letters.length <= 7 &&
    letters.every((cp) => (cp >= 0xe0061 && cp <= 0xe007a) || (cp >= 0xe0030 && cp <= 0xe0039))
  );
}

function decodeTagRun(points) {
  return points
    .filter((cp) => cp >= 0xe0020 && cp <= 0xe007e)
    .map((cp) => String.fromCharCode(cp - TAG_START))
    .join('');
}

function decodeVariationRun(points) {
  const bytes = points.map((cp) => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16));
  return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
}

function decodeZeroWidthRun(points) {
  const distinct = [...new Set(points)];
  if (distinct.length !== 2) return '';

  for (const [zero, one] of [distinct, [...distinct].reverse()]) {
    const bits = points.map((cp) => (cp === zero ? '0' : cp === one ? '1' : '')).join('');
    const bytes = [];
    for (let index = 0; index + 8 <= bits.length; index += 8) {
      bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
    }
    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
    if (decoded.length >= 2 && printableRatio(decoded) >= 0.9) return decoded;
  }

  return '';
}

export function detectSmuggling(text) {
  const value = String(text || '');
  const codePoints = [...value].map((char) => char.codePointAt(0));
  const kinds = [];
  const decodedParts = [];

  const tagRuns = collectRuns(codePoints, isTag).filter((run) => !isSubdivisionFlag(codePoints, run));
  if (tagRuns.length) {
    const decoded = tagRuns.map((run) => decodeTagRun(run.points)).filter(Boolean).join(' ');
    kinds.push({ kind: 'unicode-tags', label: 'Invisible Unicode tag characters', count: tagRuns.reduce((n, run) => n + run.points.length, 0), decoded });
    if (decoded) decodedParts.push(decoded);
  }

  const variationRuns = collectRuns(codePoints, isVariationSelector).filter((run) => run.points.length >= 3);
  if (variationRuns.length) {
    const decoded = variationRuns.map((run) => decodeVariationRun(run.points)).filter((part) => printableRatio(part) >= 0.8).join(' ');
    kinds.push({ kind: 'variation-selectors', label: 'Data hidden in variation selectors', count: variationRuns.reduce((n, run) => n + run.points.length, 0), decoded });
    if (decoded) decodedParts.push(decoded);
  }

  const zeroWidthRuns = collectRuns(codePoints, (cp) => ZERO_WIDTH.has(cp)).filter((run) => run.points.length >= 8);
  if (zeroWidthRuns.length) {
    const decoded = zeroWidthRuns.map((run) => decodeZeroWidthRun(run.points)).filter(Boolean).join(' ');
    kinds.push({ kind: 'zero-width', label: 'Long runs of zero-width characters', count: zeroWidthRuns.reduce((n, run) => n + run.points.length, 0), decoded });
    if (decoded) decodedParts.push(decoded);
  }

  const bidiCount = (value.match(BIDI) || []).length;
  if (bidiCount) {
    kinds.push({ kind: 'bidi-controls', label: 'Bidirectional control characters that reorder text', count: bidiCount, decoded: '' });
  }

  return { found: kinds.length > 0, kinds, decoded: decodedParts.join('\n') };
}

// Remove invisible payload carriers while keeping legitimate uses: emoji ZWJ
// sequences, single presentation selectors, and subdivision flags.
export function stripInvisiblePayloads(text) {
  const value = String(text || '');
  const codePoints = [...value].map((char) => char.codePointAt(0));
  const remove = new Set();

  for (const run of collectRuns(codePoints, isTag)) {
    if (isSubdivisionFlag(codePoints, run)) continue;
    for (let offset = 0; offset < run.points.length; offset += 1) remove.add(run.start + offset);
  }
  for (const run of collectRuns(codePoints, isVariationSelector)) {
    if (run.points.length < 3) continue;
    for (let offset = 0; offset < run.points.length; offset += 1) remove.add(run.start + offset);
  }
  for (const run of collectRuns(codePoints, (cp) => ZERO_WIDTH.has(cp))) {
    if (run.points.length < 4) continue;
    for (let offset = 0; offset < run.points.length; offset += 1) remove.add(run.start + offset);
  }

  return [...value]
    .filter((_char, index) => !remove.has(index))
    .join('')
    .replace(BIDI, '');
}

// ---------------------------------------------------------------------------
// Base64 payloads
// ---------------------------------------------------------------------------

const BASE64_CANDIDATE = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

function decodeBase64(encoded) {
  try {
    const binary = globalThis.atob(encoded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function findBase64Text(text) {
  const results = [];
  const value = String(text || '');

  for (const match of value.matchAll(BASE64_CANDIDATE)) {
    if (results.length >= 5) break;
    const decoded = decodeBase64(match[0]);
    if (!decoded || !/\s/.test(decoded) || printableRatio(decoded) < 0.9) continue;
    results.push({ encoded: match[0].length > 80 ? `${match[0].slice(0, 80)}…` : match[0], decoded: decoded.slice(0, 2000) });
  }

  return results;
}

const STRENGTH_ORDER = { none: 0, weak: 1, strong: 2 };

// Full analysis of one block of text: visible wording, invisible payloads,
// and base64 blobs that decode to readable text.
export function analyzeText(text) {
  const smuggling = detectSmuggling(text);
  const base64 = findBase64Text(text);
  const layers = [{ via: 'text', result: detectInstructions(text) }];

  if (smuggling.decoded) layers.push({ via: 'invisible-unicode', result: detectInstructions(smuggling.decoded) });
  for (const entry of base64) layers.push({ via: 'base64', result: detectInstructions(entry.decoded) });

  let strength = 'none';
  let score = 0;
  const matches = [];
  for (const layer of layers) {
    if (STRENGTH_ORDER[layer.result.strength] > STRENGTH_ORDER[strength]) strength = layer.result.strength;
    score = Math.max(score, layer.result.score);
    for (const match of layer.result.matches) matches.push({ ...match, via: layer.via });
  }

  return { strength, score, matches, smuggling, base64 };
}
