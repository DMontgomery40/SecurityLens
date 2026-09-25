import {
  parsePolicy,
  serializePolicy,
  resolveEffectivePolicy
} from '../../src/lib/isp/policy.js';

const codes = (list) => list.map((item) => item.code);

describe('parsePolicy', () => {
  test('parses every directive from the spec example', () => {
    const result = parsePolicy(
      "default voice; untrusted #comments, .review-body, [data-ugc]; tools 'self'; instructions /llms.txt; report-to https://securitylens.io/r/7f3c9a"
    );
    expect(result.errors).toEqual([]);
    expect(result.directives).toEqual({
      default: 'voice',
      voice: [],
      untrusted: ['#comments', '.review-body', '[data-ugc]'],
      tools: ["'self'"],
      instructions: '/llms.txt',
      reportTo: 'https://securitylens.io/r/7f3c9a'
    });
    expect(result.failedClosed).toBe(false);
  });

  test('treats an omitted default as voice', () => {
    const result = parsePolicy('untrusted .comment');
    expect(result.directives.default).toBe('voice');
    expect(result.directives.untrusted).toEqual(['.comment']);
  });

  test('matches directive names case-insensitively', () => {
    const result = parsePolicy('DEFAULT untrusted; Voice #main');
    expect(result.directives.default).toBe('untrusted');
    expect(result.directives.voice).toEqual(['#main']);
  });

  test('keeps commas inside functional pseudo-classes and quoted attribute values', () => {
    const result = parsePolicy('untrusted :is(.a, .b) > p, [title="x,y"]');
    expect(result.errors).toEqual([]);
    expect(result.directives.untrusted).toEqual([':is(.a, .b) > p', '[title="x,y"]']);
  });

  test('keeps semicolons inside quoted attribute values', () => {
    const result = parsePolicy('untrusted [data-x="a;b"]; default voice');
    expect(result.errors).toEqual([]);
    expect(result.directives.untrusted).toEqual(['[data-x="a;b"]']);
    expect(result.directives.default).toBe('voice');
  });

  test('an invalid selector invalidates only that selector', () => {
    const result = parsePolicy('untrusted .ok, ..bad, #fine');
    expect(result.directives.untrusted).toEqual(['.ok', '#fine']);
    expect(codes(result.errors)).toContain('invalid-selector');
  });

  test('an unreadable default fails closed to untrusted and keeps untrusted selectors', () => {
    const result = parsePolicy('default everyone; voice #main; untrusted .comment');
    expect(result.failedClosed).toBe(true);
    expect(result.directives.voice).toEqual([]);
    expect(result.directives.default).toBe('untrusted');
    expect(result.directives.untrusted).toEqual(['.comment']);
    expect(codes(result.errors)).toContain('invalid-default');
  });

  test.each([
    ['a repeated voice directive', 'default untrusted; voice #a; voice #b'],
    ['repeated defaults that disagree', 'default voice; default untrusted; voice #a'],
    ['a second header that declares default untrusted', 'voice #main, default untrusted; untrusted .x'],
    ['a second header combined after a default untrusted policy', 'default untrusted; voice #main, voice #side']
  ])('failing closed never widens trust: %s', (_label, policy) => {
    const result = parsePolicy(policy);
    expect(result.failedClosed).toBe(true);
    expect(result.directives.voice).toEqual([]);
    expect(result.directives.default).toBe('untrusted');
  });

  test('failing closed keeps an omitted default as voice when nothing asked for untrusted', () => {
    const result = parsePolicy('voice #a; voice #b; untrusted .c');
    expect(result.failedClosed).toBe(true);
    expect(result.directives.default).toBe('voice');
    expect(result.directives.untrusted).toEqual(['.c']);
  });

  test('a repeated voice directive fails closed', () => {
    const result = parsePolicy('voice #main; voice #sidebar; untrusted .c');
    expect(result.failedClosed).toBe(true);
    expect(result.directives.voice).toEqual([]);
    expect(result.directives.untrusted).toEqual(['.c']);
    expect(codes(result.errors)).toContain('duplicate-directive');
  });

  test('a repeated untrusted directive combines both lists', () => {
    const result = parsePolicy('untrusted .a; untrusted .b');
    expect(result.failedClosed).toBe(false);
    expect(result.directives.untrusted).toEqual(['.a', '.b']);
  });

  test('detects header fields that HTTP combined with a comma and fails closed', () => {
    const combined = 'default voice; voice #main, default untrusted; untrusted .x';
    const result = parsePolicy(combined);
    expect(result.failedClosed).toBe(true);
    expect(result.directives.voice).toEqual([]);
    expect(codes(result.errors)).toContain('combined-policies');
  });

  test('ignores unknown directives with a warning', () => {
    const result = parsePolicy('untrusted .c; frobnicate yes');
    expect(result.directives.untrusted).toEqual(['.c']);
    expect(codes(result.warnings)).toContain('unknown-directive');
    expect(result.errors).toEqual([]);
  });

  test("'none' in tools wins over any other source", () => {
    const result = parsePolicy("tools 'none' https://widgets.example.com");
    expect(result.directives.tools).toEqual(["'none'"]);
    expect(codes(result.warnings)).toContain('tools-none-combined');
  });

  test('rejects a tools source that is not an origin', () => {
    const result = parsePolicy("tools 'self' not-a-url");
    expect(result.directives.tools).toEqual(["'self'"]);
    expect(codes(result.errors)).toContain('invalid-tool-source');
  });

  test('drops a report-to endpoint that is not absolute https', () => {
    const result = parsePolicy('report-to http://example.com/r');
    expect(result.directives.reportTo).toBeNull();
    expect(codes(result.errors)).toContain('invalid-report-to');
  });

  test('warns on an empty policy', () => {
    const result = parsePolicy('   ');
    expect(codes(result.warnings)).toContain('empty-policy');
  });

  test('warns when a voice selector can be spoofed by user content', () => {
    const spoofable = parsePolicy('voice .official');
    expect(codes(spoofable.warnings)).toContain('spoofable-voice-selector');
    const structural = parsePolicy('voice #main, body > main > article');
    expect(codes(structural.warnings)).not.toContain('spoofable-voice-selector');
  });
});

describe('serializePolicy', () => {
  const samples = [
    "default voice; untrusted #comments, .review-body; tools 'self'; report-to https://securitylens.io/r/abc",
    'default untrusted; voice #main, #site-header',
    'untrusted [data-x="a;b"], :is(.a, .b) > p',
    "tools 'none'; instructions /llms.txt"
  ];

  test.each(samples)('round-trips %s', (sample) => {
    const first = parsePolicy(sample);
    const second = parsePolicy(serializePolicy(first.directives));
    expect(second.directives).toEqual(first.directives);
    expect(second.errors).toEqual([]);
  });

  test('omits empty directives', () => {
    expect(
      serializePolicy({ default: 'voice', voice: [], untrusted: ['.c'], tools: null, instructions: null, reportTo: null })
    ).toBe('default voice; untrusted .c');
  });
});

describe('resolveEffectivePolicy', () => {
  test('returns no policy when no source is present', () => {
    const effective = resolveEffectivePolicy({});
    expect(effective.present).toBe(false);
    expect(effective.source).toBeNull();
  });

  test('the header is authoritative and meta cannot grant voice', () => {
    const effective = resolveEffectivePolicy({
      header: 'untrusted .comment',
      meta: 'voice .anything; untrusted .review; default untrusted'
    });
    expect(effective.source).toBe('header');
    expect(effective.directives.voice).toEqual([]);
    expect(effective.directives.default).toBe('voice');
    expect(effective.directives.untrusted).toEqual(['.comment', '.review']);
  });

  test('meta is authoritative when there is no header', () => {
    const effective = resolveEffectivePolicy({ meta: 'default untrusted; voice #main', wellKnown: 'untrusted .x' });
    expect(effective.source).toBe('meta');
    expect(effective.directives.default).toBe('untrusted');
    expect(effective.directives.voice).toEqual(['#main']);
    expect(effective.directives.untrusted).toEqual(['.x']);
  });

  test('the well-known file applies only when nothing else is present', () => {
    const effective = resolveEffectivePolicy({ wellKnown: "untrusted .x; tools 'self'" });
    expect(effective.source).toBe('well-known');
    expect(effective.directives.tools).toEqual(["'self'"]);
  });

  test('a failed-closed authoritative policy grants no voice', () => {
    const effective = resolveEffectivePolicy({ header: 'voice #a; voice #b' });
    expect(effective.failedClosed).toBe(true);
    expect(effective.directives.voice).toEqual([]);
  });
});

describe('selector validation', () => {
  const { isValidSelector } = require('../../src/lib/isp/policy.js');

  test.each(['..bad', 'p >', '> p', '#', '[x', 'div!!', ':is()'])('rejects %s', (selector) => {
    expect(isValidSelector(selector)).toBe(false);
  });

  test.each([':is(.a, .b) > p', '#main', 'body > main article', '[data-ugc]', 'shreddit-comment', '.comment-body p', '#a\\.b'])(
    'accepts %s',
    (selector) => {
      expect(isValidSelector(selector)).toBe(true);
    }
  );
});
