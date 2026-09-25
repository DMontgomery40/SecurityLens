// Reference implementation of Instruction Security Policy zone resolution,
// plus inference and findings for pages that have no policy yet.
// Isomorphic: runs in Netlify Functions, the CLI, and the browser.

import * as cheerio from 'cheerio';
import { resolveEffectivePolicy, parsePolicy, isSpoofableSelector, serializePolicy, POLICY_HEADER } from './policy.js';
import { analyzeText, normalizeForMatching } from './detect.js';
import { extractHiddenRules, hiddenKindForElement, HIDDEN_LABELS } from './hidden.js';
import { inferUserContent } from './ugc.js';
import { findDeclarativeTools, findImperativeTools, originOf } from './tools.js';

export const REPORT_VERSION = 1;
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const BLOCK_TAGS = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'caption', 'dd', 'details', 'dialog', 'div', 'dl', 'dt',
  'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup',
  'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'summary', 'table', 'tbody', 'td', 'tfoot', 'th',
  'thead', 'tr', 'ul'
]);
const QUOTE_TAGS = new Set(['blockquote', 'q', 'code', 'pre', 'samp', 'kbd']);
const FRAME_TAGS = new Set(['iframe', 'frame', 'object', 'embed']);
const TEXT_ATTRIBUTES = ['alt', 'title', 'aria-label', 'aria-description', 'placeholder'];
const MAX_DEPTH = 1500;
const MAX_FINDINGS_PER_KIND = 40;

function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : headers[key];
}

function elementPath(element) {
  const parts = [];
  let node = element;
  while (node && node.type === 'tag' && parts.length < 4) {
    const tag = node.name;
    if (node.attribs?.id && /^-?[_a-zA-Z][_a-zA-Z0-9-]*$/.test(node.attribs.id)) {
      parts.unshift(`#${node.attribs.id}`);
      break;
    }
    const siblings = (node.parent?.children || []).filter((child) => child.type === 'tag' && child.name === tag);
    parts.unshift(siblings.length > 1 ? `${tag}:nth-of-type(${siblings.indexOf(node) + 1})` : tag);
    node = node.parent;
  }
  return parts.join(' > ');
}

function excerpt(text, length = 280) {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > length ? `${clean.slice(0, length)}…` : clean;
}

export function analyzeDocument({ html, url = null, headers = {}, wellKnown = null, source, maxTextChars = 300000 } = {}) {
  const $ = cheerio.load(String(html || ''));
  const pageOrigin = originOf(url);
  const regions = [];
  const segments = [];
  const findings = [];
  const inlineScripts = [];
  const scriptOrigins = new Set();
  const frames = [];
  const attributeGrantAttempts = [];
  let scriptCount = 0;
  let truncated = false;
  let totalChars = 0;

  // ---- Policy -------------------------------------------------------------
  const metaElements = $('meta')
    .toArray()
    .filter((element) => (element.attribs['http-equiv'] || '').trim().toLowerCase() === POLICY_HEADER.toLowerCase());
  const headMetas = metaElements.filter((element) => element.parent?.name === 'head');
  const misplacedMetas = metaElements.filter((element) => element.parent?.name !== 'head');

  const policy = resolveEffectivePolicy({
    header: getHeader(headers, POLICY_HEADER),
    meta: headMetas.length ? headMetas[0].attribs.content || '' : undefined,
    wellKnown: typeof wellKnown === 'string' ? wellKnown : undefined
  });
  const directives = policy.directives;

  function selectAll(selector) {
    try {
      return $(selector).toArray();
    } catch {
      return null;
    }
  }

  const untrustedMatches = new Map();
  const unmatchedUntrusted = [];
  for (const selector of directives.untrusted) {
    const matched = selectAll(selector);
    if (!matched || matched.length === 0) {
      unmatchedUntrusted.push(selector);
      continue;
    }
    for (const element of matched) if (!untrustedMatches.has(element)) untrustedMatches.set(element, selector);
  }

  const voiceMatches = new Map();
  const unmatchedVoice = [];
  for (const selector of directives.voice) {
    const matched = selectAll(selector);
    if (!matched || matched.length === 0) {
      unmatchedVoice.push(selector);
      continue;
    }
    for (const element of matched) if (!voiceMatches.has(element)) voiceMatches.set(element, selector);
  }

  const stylesheetHidden = new Map();
  for (const style of $('style').toArray()) {
    for (const rule of extractHiddenRules($(style).text())) {
      for (const element of selectAll(rule.selector) || []) {
        if (!stylesheetHidden.has(element)) stylesheetHidden.set(element, rule.kind);
      }
    }
  }

  // ---- Walk -----------------------------------------------------------------
  let current = null;

  function flush() {
    if (!current) return;
    const text = current.pre ? current.parts.join('').replace(/^\n+|\s+$/g, '') : current.parts.join('').replace(/\s+/g, ' ').trim();
    if (text) {
      segments.push({
        id: `s${segments.length + 1}`,
        zone: current.zone,
        basis: current.basis,
        regionId: current.regionId,
        quoted: current.quoted,
        hiddenKind: current.hiddenKind,
        voiceSelector: current.voiceSelector,
        spoofableVoice: current.spoofableVoice,
        text
      });
    }
    current = null;
  }

  function newRegion(fields) {
    const region = { id: `r${regions.length + 1}`, textLength: 0, excerpt: '', ...fields };
    regions.push(region);
    return region;
  }

  function appendText(text, ctx) {
    if (!text) return;
    if (totalChars >= maxTextChars) {
      truncated = true;
      return;
    }
    totalChars += text.length;

    const zone = ctx.hidden ? 'hidden' : ctx.zone;
    const regionId = ctx.hidden ? ctx.hiddenRegionId : ctx.regionId;
    const key = `${zone}|${regionId}|${ctx.quoted}|${ctx.basis}|${ctx.voiceSelector}`;
    if (!current || current.key !== key) {
      flush();
      current = {
        key,
        zone,
        regionId,
        basis: ctx.hidden ? 'hidden' : ctx.basis,
        quoted: ctx.quoted,
        pre: ctx.pre,
        hiddenKind: ctx.hidden || null,
        voiceSelector: ctx.hidden ? null : ctx.voiceSelector,
        spoofableVoice: ctx.hidden ? false : ctx.spoofableVoice,
        parts: []
      };
    }
    current.parts.push(text);
  }

  function visitComment(node, ctx) {
    const text = (node.data || '').trim();
    if (text.length < 12) return;
    const analysis = analyzeText(text);
    if (analysis.strength === 'none' && !analysis.smuggling.found) return;
    const region = newRegion({ zone: 'hidden', basis: 'hidden', hiddenKind: 'html-comment', label: 'HTML comment', reason: 'Hidden with an HTML comment', parentZone: ctx.zone });
    flush();
    appendText(text, { ...ctx, hidden: 'html-comment', hiddenRegionId: region.id });
    flush();
  }

  function visit(node, ctx, depth) {
    if (depth > MAX_DEPTH) return;

    if (node.type === 'text') {
      appendText(ctx.pre ? node.data : node.data.replace(/\s+/g, ' '), ctx);
      return;
    }
    if (node.type === 'comment') {
      visitComment(node, ctx);
      return;
    }
    if (node.type === 'script') {
      scriptCount += 1;
      if (node.attribs?.src) {
        const origin = originOf(node.attribs.src, url || undefined);
        if (origin) scriptOrigins.add(origin);
      } else {
        inlineScripts.push($(node).text());
      }
      return;
    }
    if (node.type === 'style' || node.type === 'directive') return;
    if (node.type !== 'tag' && node.type !== 'root') {
      for (const child of node.children || []) visit(child, ctx, depth + 1);
      return;
    }

    const tag = (node.name || '').toLowerCase();
    if (tag === 'head') return;

    if (FRAME_TAGS.has(tag)) {
      const src = node.attribs?.src || node.attribs?.data;
      if (src) {
        let absolute = src;
        try {
          absolute = new URL(src, url || undefined).href;
        } catch {
          absolute = src;
        }
        const origin = originOf(src, url || undefined);
        const crossOrigin = Boolean(origin) && origin !== pageOrigin;
        frames.push({ src: absolute, origin, crossOrigin });
        if (crossOrigin) {
          newRegion({ zone: 'untrusted', basis: 'embed', label: `Embedded content from ${origin}`, reason: 'Cross-origin frame (not fetched)', suggestedSelector: `${tag}[src^="${origin}"]`, covered: ctx.declaredUntrusted });
        }
      }
      return;
    }

    const next = { ...ctx };
    const attribs = node.attribs || {};
    const ispAttribute = typeof attribs['data-isp'] === 'string' ? attribs['data-isp'].trim().toLowerCase() : null;

    if (!ctx.declaredUntrusted) {
      const selector = untrustedMatches.get(node);
      if (selector || ispAttribute === 'untrusted') {
        const basis = selector ? 'policy' : 'attribute';
        const region = newRegion({
          zone: 'untrusted',
          basis,
          label: 'Declared untrusted',
          reason: selector ? `Matches untrusted selector "${selector}"` : 'Marked data-isp="untrusted"',
          selector: selector || '[data-isp="untrusted"]',
          suggestedSelector: selector || elementPath(node),
          covered: true
        });
        Object.assign(next, { zone: 'untrusted', declaredUntrusted: true, basis, regionId: region.id, voiceSelector: null, spoofableVoice: false });
        if (ctx.inferredRegion) ctx.inferredRegion.containsDeclared = true;
      }
    }

    if (ispAttribute !== null && ispAttribute !== 'untrusted') {
      attributeGrantAttempts.push({ value: attribs['data-isp'], path: elementPath(node), insideUserContent: ctx.declaredUntrusted || ctx.inferredUntrusted });
    }

    let voiceGranted = false;
    if (!next.declaredUntrusted && voiceMatches.has(node)) {
      const selector = voiceMatches.get(node);
      voiceGranted = true;
      Object.assign(next, { zone: 'voice', basis: 'policy', voiceSelector: selector, spoofableVoice: isSpoofableSelector(selector), inferredUntrusted: false, inferredRegion: null });
      if (ctx.inferredUntrusted) next.regionId = null;
    }

    if (!next.declaredUntrusted && !next.inferredUntrusted && !voiceGranted) {
      const inferred = inferUserContent(node);
      if (inferred) {
        const region = newRegion({ zone: 'untrusted', basis: 'inferred', ...inferred, selector: null, covered: false, containsDeclared: false });
        Object.assign(next, { zone: 'untrusted', inferredUntrusted: true, inferredRegion: region, basis: 'inferred', regionId: region.id, voiceSelector: null, spoofableVoice: false });
      }
    }

    if (!ctx.hidden) {
      let hiddenKind = null;
      if (tag === 'noscript') hiddenKind = 'noscript';
      else if (tag === 'template') hiddenKind = 'template';
      else hiddenKind = hiddenKindForElement(node, stylesheetHidden);

      if (hiddenKind) {
        const region = newRegion({ zone: 'hidden', basis: 'hidden', hiddenKind, label: 'Hidden text', reason: `Hidden with ${HIDDEN_LABELS[hiddenKind]}`, parentZone: next.zone, suggestedSelector: elementPath(node) });
        Object.assign(next, { hidden: hiddenKind, hiddenRegionId: region.id });
      }
    }

    if (QUOTE_TAGS.has(tag)) next.quoted = true;
    if (tag === 'pre') next.pre = true;

    if (tag === 'noscript') {
      flush();
      appendText($(node).text().replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '), next);
      flush();
      return;
    }

    if (BLOCK_TAGS.has(tag)) {
      if (current && tag === 'br') current.parts.push(current.pre ? '\n' : ' ');
      flush();
    }
    for (const child of node.children || []) visit(child, next, depth + 1);
    if (BLOCK_TAGS.has(tag)) flush();
  }

  const rootContext = {
    zone: policy.present ? directives.default : 'voice',
    basis: policy.present ? 'policy-default' : 'default',
    declaredUntrusted: false,
    inferredUntrusted: false,
    inferredRegion: null,
    regionId: null,
    hidden: null,
    hiddenRegionId: null,
    quoted: false,
    pre: false,
    voiceSelector: null,
    spoofableVoice: false
  };

  const body = $('body').get(0);
  visit(body || $.root().get(0), rootContext, 0);
  flush();

  // Scripts in head also count toward coverage and tool discovery.
  $('head script').each((_index, element) => {
    scriptCount += 1;
    if (element.attribs?.src) {
      const origin = originOf(element.attribs.src, url || undefined);
      if (origin) scriptOrigins.add(origin);
    } else {
      inlineScripts.push($(element).text());
    }
  });

  // ---- Region text --------------------------------------------------------
  const regionText = new Map();
  for (const segment of segments) {
    if (!segment.regionId) continue;
    regionText.set(segment.regionId, `${regionText.get(segment.regionId) || ''} ${segment.text}`);
  }
  for (const region of regions) {
    const text = (regionText.get(region.id) || '').trim();
    region.textLength = text.length;
    region.excerpt = excerpt(text);
  }

  // ---- Findings -------------------------------------------------------------
  const perKind = new Map();
  function addFinding(finding) {
    const count = perKind.get(finding.kind) || 0;
    if (count >= MAX_FINDINGS_PER_KIND) return;
    perKind.set(finding.kind, count + 1);
    findings.push({ id: `f${findings.length + 1}`, ...finding });
  }

  const regionById = new Map(regions.map((region) => [region.id, region]));
  const PAYLOAD_KINDS = new Set(['unicode-tags', 'variation-selectors', 'zero-width']);

  for (const segment of segments) {
    const analysis = analyzeText(segment.text);
    const region = segment.regionId ? regionById.get(segment.regionId) : null;
    const visibleMatches = analysis.matches.filter((match) => match.via !== 'invisible-unicode');
    const visibleStrength = visibleMatches.some((match) => match.weight >= 3) || visibleMatches.reduce((sum, match) => sum + match.weight, 0) >= 3
      ? 'strong'
      : visibleMatches.length
        ? 'weak'
        : 'none';
    const decodedBase64 = analysis.base64.find((entry) => analysis.matches.some((match) => match.via === 'base64' && entry.decoded.includes(match.match.slice(0, 20))));
    const base = {
      ...(decodedBase64 ? { decoded: decodedBase64.decoded.slice(0, 600), decodedFrom: 'base64' } : {}),
      zone: segment.zone,
      regionId: segment.regionId,
      segmentId: segment.id,
      excerpt: excerpt(normalizeForMatching(segment.text), 320),
      rules: analysis.matches.map(({ rule, label, match, via }) => ({ rule, label, match, via }))
    };

    const payloads = analysis.smuggling.kinds.filter((kind) => PAYLOAD_KINDS.has(kind.kind));
    if (payloads.length) {
      const instructive = analysis.matches.some((match) => match.via === 'invisible-unicode');
      addFinding({
        ...base,
        kind: 'invisible-payload',
        severity: instructive ? 'critical' : 'high',
        title: 'Invisible text payload',
        detail: `${payloads.map((kind) => kind.label).join(' and ')} carry a message people can't see${instructive ? ', and it gives agents instructions' : ''}.`,
        decoded: analysis.smuggling.decoded.slice(0, 600),
        decodedFrom: 'invisible-unicode',
        remediation: 'Strip invisible Unicode from user input before storing or rendering it.'
      });
    }
    if (analysis.smuggling.kinds.some((kind) => kind.kind === 'bidi-controls')) {
      addFinding({
        ...base,
        kind: 'bidi-controls',
        severity: 'low',
        title: 'Text-reordering characters',
        detail: 'Bidirectional control characters can make text read differently to people and to agents.',
        remediation: 'Remove bidirectional control characters unless the content needs them.'
      });
    }

    if (visibleStrength === 'none') continue;

    if (segment.zone === 'hidden') {
      addFinding({
        ...base,
        kind: 'hidden-instruction',
        severity: visibleStrength === 'strong' ? 'critical' : 'high',
        hiddenKind: segment.hiddenKind,
        title: 'Hidden instructions',
        detail: `Text hidden with ${HIDDEN_LABELS[segment.hiddenKind] || 'styling'} tells agents what to do. People can't see it. Agents read it.`,
        remediation: 'Remove the hidden text. If it came from user input, find how it got past sanitization.'
      });
    } else if (segment.zone === 'untrusted') {
      const contained = segment.basis === 'policy' || segment.basis === 'attribute';
      addFinding({
        ...base,
        kind: 'instruction-in-untrusted',
        severity: visibleStrength === 'strong' ? (contained || analysis.quoted ? 'medium' : 'high') : 'low',
        contained,
        quoted: analysis.quoted,
        title: visibleStrength === 'strong' ? (analysis.quoted ? 'Quoted instructions inside user content' : 'Instructions inside user content') : 'Instruction-like wording in user content',
        detail: contained
          ? 'This region is declared untrusted. Agents that honor the policy treat it as information, not orders.'
          : `Someone other than the site wrote this, it tells agents what to do, and nothing on the page marks it as not the site speaking.`,
        remediation: contained ? 'Moderate or remove the content.' : `Declare the region untrusted, for example "untrusted ${region?.suggestedSelector || region?.selector || '…'}".`
      });
    } else if (segment.zone === 'voice' && visibleStrength === 'strong') {
      if (segment.voiceSelector && segment.spoofableVoice) {
        addFinding({
          ...base,
          kind: 'instruction-via-spoofable-voice',
          severity: 'high',
          title: 'Instructions reach site voice through a spoofable selector',
          detail: `The voice selector "${segment.voiceSelector}" matches this text, and user content could carry the same class or attribute.`,
          remediation: 'Replace the selector with an id or structural selector.'
        });
      } else {
        addFinding({
          ...base,
          kind: 'instruction-in-voice',
          severity: 'info',
          title: segment.quoted ? 'Quoted instruction example in site voice' : 'Instruction-like text in site voice',
          detail: segment.quoted
            ? 'This reads like a quoted example. Agents will attribute it to the site.'
            : 'The site itself appears to address agents here. Check that it is intentional.',
          remediation: 'If this text came from users, declare its region untrusted.'
        });
      }
    }
  }

  // Attribute text: alt, title, aria labels, and head metadata.
  const attributeSources = [];
  $('body [alt], body [title], body [aria-label], body [aria-description], body [placeholder]').each((_index, element) => {
    for (const name of TEXT_ATTRIBUTES) {
      const value = element.attribs?.[name];
      if (value && value.trim().length >= 12) attributeSources.push({ label: `${name} attribute`, value, element });
    }
  });
  $('head meta[name="description"], head meta[property^="og:"], head meta[name^="twitter:"]').each((_index, element) => {
    const value = element.attribs?.content;
    if (value && value.trim().length >= 12) attributeSources.push({ label: `${element.attribs.name || element.attribs.property} metadata`, value, element });
  });

  for (const source of attributeSources) {
    const analysis = analyzeText(source.value);
    if (analysis.strength === 'none' && !analysis.smuggling.found) continue;
    const payload = analysis.smuggling.kinds.some((kind) => PAYLOAD_KINDS.has(kind.kind));
    addFinding({
      kind: payload ? 'invisible-payload' : 'attribute-instruction',
      severity: payload ? (analysis.strength === 'strong' ? 'critical' : 'high') : analysis.strength === 'strong' ? 'high' : 'low',
      zone: 'hidden',
      regionId: null,
      title: payload ? 'Invisible text payload' : `Instructions in the ${source.label}`,
      detail: `Agents read ${source.label} text even though most people never see it.`,
      excerpt: excerpt(normalizeForMatching(source.value), 320),
      location: elementPath(source.element),
      decoded: payload ? analysis.smuggling.decoded.slice(0, 600) : undefined,
      rules: analysis.matches.map(({ rule, label, match, via }) => ({ rule, label, match, via })),
      remediation: 'Rewrite the attribute. If users can set it, sanitize it like visible text.'
    });
  }

  // Reflected request parameters.
  if (url) {
    let params = [];
    try {
      params = [...new URL(url).searchParams.entries()];
    } catch {
      params = [];
    }
    const voiceText = normalizeForMatching(segments.filter((segment) => segment.zone === 'voice').map((segment) => segment.text).join(' ')).toLowerCase();
    for (const [name, value] of params) {
      const needle = normalizeForMatching(value).toLowerCase();
      if (needle.length < 8 || !/[a-z]/i.test(needle)) continue;
      if (voiceText.includes(needle)) {
        addFinding({
          kind: 'reflected-input',
          severity: 'medium',
          zone: 'voice',
          regionId: null,
          parameter: name,
          title: 'Request input echoed as site voice',
          detail: `The "${name}" parameter appears in the page. Anyone can craft a link that makes this site say whatever they want to an agent.`,
          excerpt: excerpt(value, 200),
          remediation: 'Wrap the echoed input in an element marked untrusted.'
        });
      }
    }
  }

  // Policy findings.
  if (!policy.present) {
    const inferredCount = regions.filter((region) => region.zone === 'untrusted').length;
    addFinding({
      kind: 'no-policy',
      severity: 'info',
      zone: null,
      regionId: null,
      title: 'No Instruction Security Policy',
      detail: inferredCount
        ? `Agents have to guess who is speaking. ${inferredCount === 1 ? 'One region looks' : `${inferredCount} regions look`} like user content.`
        : 'Agents have to guess who is speaking on this page.',
      remediation: 'Generate a policy from this analysis and send it as a header.'
    });
  }

  if (policy.failedClosed) {
    addFinding({
      kind: 'policy-failed-closed',
      severity: 'medium',
      title: 'Policy failed closed',
      detail: 'Errors in the policy mean agents discard every voice grant. Untrusted selectors still apply.',
      remediation: 'Fix the errors listed with the policy.'
    });
  }

  for (const error of policy.errors) {
    addFinding({ kind: 'policy-error', severity: 'medium', title: 'Policy error', detail: error.message, code: error.code, source: error.source, remediation: 'Correct the directive.' });
  }

  for (const warning of policy.warnings) {
    if (warning.code === 'spoofable-voice-selector') {
      addFinding({ kind: 'spoofable-voice-selector', severity: 'medium', title: 'Spoofable voice selector', detail: warning.message, selector: warning.selector, source: warning.source, remediation: 'Use an id or structural selector for voice regions.' });
    } else {
      addFinding({ kind: 'policy-warning', severity: warning.code === 'unknown-directive' ? 'info' : 'low', title: 'Policy warning', detail: warning.message, code: warning.code, source: warning.source, remediation: 'Review the directive.' });
    }
  }

  for (const element of misplacedMetas) {
    const content = element.attribs.content || '';
    const parsed = parsePolicy(content);
    const grants = parsed.directives.voice.length > 0 || /(^|;)\s*default\s/i.test(content);
    addFinding({
      kind: 'policy-meta-outside-head',
      severity: grants ? 'high' : 'medium',
      title: 'Policy meta element outside head was ignored',
      detail: grants
        ? 'A policy that grants voice appears in the page body. That is where injected content lands, so agents ignore it.'
        : 'Policy meta elements only count inside head.',
      excerpt: excerpt(content, 200),
      remediation: 'Move the policy to a header or into head. If you did not put it there, find how it got into the page.'
    });
  }

  if (headMetas.length > 1) {
    addFinding({ kind: 'duplicate-policy-meta', severity: 'low', title: 'More than one policy meta element', detail: 'Only the first policy meta element in head counts.', remediation: 'Keep one policy meta element.' });
  }

  for (const selector of unmatchedUntrusted) {
    addFinding({
      kind: 'selector-matches-nothing',
      severity: policy.source === 'well-known' ? 'info' : 'low',
      selector,
      title: 'Untrusted selector matches nothing',
      detail: `"${selector}" matches no element on this page.`,
      remediation: 'Check the selector against the page markup.'
    });
  }

  for (const attempt of attributeGrantAttempts) {
    addFinding({
      kind: 'attribute-cannot-grant-voice',
      severity: attempt.insideUserContent ? 'medium' : 'low',
      title: `data-isp="${attempt.value}" has no effect`,
      detail: attempt.insideUserContent
        ? 'User content tried to mark itself trusted. The attribute can only mark content untrusted.'
        : 'The attribute can only mark content untrusted. Grant voice in the policy instead.',
      location: attempt.path,
      remediation: 'Remove the attribute.'
    });
  }

  if (policy.present) {
    for (const region of regions) {
      if (region.basis === 'inferred' && !region.containsDeclared) {
        addFinding({
          kind: 'undeclared-user-content',
          severity: 'medium',
          regionId: region.id,
          zone: 'untrusted',
          title: 'User content the policy leaves in site voice',
          detail: `${region.label} (${region.reason}) looks like user content, but the policy doesn't mark it untrusted.`,
          excerpt: region.excerpt,
          remediation: `Add "${region.suggestedSelector}" to the untrusted directive.`
        });
      }
    }
  }

  // ---- Tools ----------------------------------------------------------------
  const declarative = findDeclarativeTools($, pageOrigin, directives.tools);
  const imperative = findImperativeTools(inlineScripts, pageOrigin, directives.tools);
  for (const tool of [...declarative, ...imperative]) {
    const text = [tool.description, ...tool.params.map((param) => param.description)].filter(Boolean).join('\n');
    const analysis = analyzeText(text);
    const payload = analysis.smuggling.kinds.some((kind) => PAYLOAD_KINDS.has(kind.kind));
    if (analysis.strength !== 'none' || payload) {
      addFinding({
        kind: 'tool-description-instruction',
        severity: payload ? 'critical' : analysis.strength === 'strong' ? 'high' : 'medium',
        title: `Tool "${tool.name || 'unnamed'}" carries instructions`,
        detail: 'Agents read tool descriptions as guidance. This one contains instruction-shaped text.',
        excerpt: excerpt(normalizeForMatching(text), 320),
        rules: analysis.matches.map(({ rule, label, match, via }) => ({ rule, label, match, via })),
        remediation: 'Describe only what the tool does.'
      });
    }
    if (tool.allowed === false) {
      addFinding({
        kind: 'tools-not-allowed',
        severity: 'medium',
        title: `Tool "${tool.name || 'unnamed'}" is not allowed by the policy`,
        detail: `The page registers this tool, but the tools directive is "${directives.tools.join(' ')}".`,
        remediation: 'Update the tools directive or remove the tool.'
      });
    }
  }
  if (policy.present && directives.tools === null && declarative.length + imperative.length > 0) {
    addFinding({ kind: 'tools-undeclared', severity: 'info', title: 'Tools without a tools directive', detail: 'The page exposes agent tools, and the policy does not say which origins may register them.', remediation: "Add tools 'self'." });
  }

  const hiddenWithText = regions.filter((region) => region.zone === 'hidden' && region.textLength >= 40);
  if (hiddenWithText.length && !findings.some((finding) => finding.kind === 'hidden-instruction')) {
    addFinding({
      kind: 'hidden-text',
      severity: 'info',
      title: 'Hidden text agents will read',
      detail: `${hiddenWithText.length} hidden region${hiddenWithText.length === 1 ? '' : 's'} contain text. None of it reads like instructions.`,
      remediation: 'No action needed unless users can control that text.'
    });
  }

  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));

  // ---- Summary --------------------------------------------------------------
  const chars = { voice: 0, untrusted: 0, hidden: 0 };
  for (const segment of segments) chars[segment.zone] += segment.text.length;
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length]));

  return {
    version: REPORT_VERSION,
    url,
    title: $('title').first().text().trim() || null,
    analyzedAt: new Date().toISOString(),
    mode: policy.present ? 'declared' : 'inferred',
    policy: {
      present: policy.present,
      source: policy.source,
      directives,
      serialized: policy.present ? serializePolicy(directives) : null,
      failedClosed: policy.failedClosed,
      errors: policy.errors,
      warnings: policy.warnings,
      sources: policy.sources.map(({ source: from, raw }) => ({ source: from, raw })),
      unmatchedVoice
    },
    regions,
    segments,
    findings,
    tools: { declarative, imperative, scriptOrigins: [...scriptOrigins] },
    summary: {
      counts,
      chars,
      regions: {
        untrusted: regions.filter((region) => region.zone === 'untrusted').length,
        hidden: regions.filter((region) => region.zone === 'hidden').length
      }
    },
    coverage: {
      source: source || (url ? 'server-html' : 'pasted-html'),
      scriptsNotExecuted: scriptCount > 0,
      likelyScriptRendered: scriptCount > 0 && chars.voice + chars.untrusted < 200,
      frames,
      truncated,
      htmlBytes: String(html || '').length
    }
  };
}
