// Detection of text that a sighted reader cannot see but an agent reading
// the HTML will. Works from inline styles, same-document stylesheets, and
// common utility class names, since the analyzer has no layout engine.

export const HIDDEN_LABELS = {
  'hidden-attribute': 'the hidden attribute',
  'display-none': 'display: none',
  'visibility-hidden': 'visibility: hidden',
  'zero-opacity': 'zero opacity',
  'zero-font': 'a zero font size',
  'transparent-text': 'transparent text',
  camouflaged: 'text colored like its background',
  offscreen: 'offscreen positioning',
  clipped: 'clipping',
  'zero-size': 'a zero-size box',
  'hidden-class': 'a hiding class',
  'visually-hidden': 'a screen-reader-only class',
  'html-comment': 'an HTML comment',
  noscript: 'a noscript block',
  template: 'a template element'
};

export function parseDeclarations(text) {
  const declarations = new Map();
  for (const part of String(text || '').split(';')) {
    const index = part.indexOf(':');
    if (index === -1) continue;
    const property = part.slice(0, index).trim().toLowerCase();
    const value = part
      .slice(index + 1)
      .replace(/!important/i, '')
      .trim()
      .toLowerCase();
    if (property) declarations.set(property, value);
  }
  return declarations;
}

function lengthValue(value) {
  const match = String(value || '').match(/^(-?\d*\.?\d+)\s*(px|pt|em|rem|%|vw|vh)?$/);
  if (!match) return null;
  return { number: Number.parseFloat(match[1]), unit: match[2] || '' };
}

function isTinyFont(value) {
  const length = lengthValue(value);
  if (!length) return false;
  if (length.number <= 0) return true;
  if (length.unit === 'px' || length.unit === 'pt') return length.number < 2;
  if (length.unit === 'em' || length.unit === 'rem') return length.number < 0.1;
  if (length.unit === '%') return length.number < 5;
  return false;
}

function isFarOffscreen(value) {
  const length = lengthValue(value);
  return Boolean(length) && length.number <= -500 && (length.unit === 'px' || length.unit === 'em' || length.unit === 'rem');
}

function isZeroLength(value) {
  const length = lengthValue(value);
  return Boolean(length) && length.number === 0;
}

function isTransparentColor(value) {
  if (!value) return false;
  if (value === 'transparent') return true;
  if (/^#([0-9a-f]{3}0|[0-9a-f]{6}00)$/.test(value)) return true;
  const alpha = value.match(/^(rgba|hsla)\(.*[,/]\s*(0*\.?0+%?)\s*\)$/);
  return Boolean(alpha);
}

function normalizeColor(value) {
  const named = { white: '#ffffff', black: '#000000' };
  const color = named[value] || value;
  const short = color.match(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/);
  if (short) return `#${short[1]}${short[1]}${short[2]}${short[2]}${short[3]}${short[3]}`;
  const rgb = color.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/);
  if (rgb) return `#${[rgb[1], rgb[2], rgb[3]].map((n) => Number(n).toString(16).padStart(2, '0')).join('')}`;
  return color;
}

export function hiddenKindFromDeclarations(declarations) {
  const get = (property) => declarations.get(property);

  if (get('display') === 'none') return 'display-none';
  if (['hidden', 'collapse'].includes(get('visibility'))) return 'visibility-hidden';
  if (get('opacity') !== undefined) {
    const opacity = lengthValue(get('opacity'));
    if (opacity && opacity.number === 0) return 'zero-opacity';
  }
  if (get('font-size') !== undefined && isTinyFont(get('font-size'))) return 'zero-font';
  if (isTransparentColor(get('color'))) return 'transparent-text';

  const background = get('background-color') || get('background');
  if (get('color') && background && normalizeColor(get('color')) === normalizeColor(background.split(/\s+/)[0])) {
    return 'camouflaged';
  }

  const positioned = ['absolute', 'fixed'].includes(get('position'));
  if (positioned && ['left', 'top', 'right', 'bottom'].some((side) => isFarOffscreen(get(side)))) return 'offscreen';
  if (isFarOffscreen(get('text-indent'))) return 'offscreen';
  if (/^rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)$/.test(get('clip') || '')) return 'clipped';
  if (/^inset\(\s*(50|100)%\s*\)$/.test(get('clip-path') || '')) return 'clipped';

  const overflowHidden = (get('overflow') || '').includes('hidden');
  const zeroBox = ['width', 'height', 'max-width', 'max-height'].some((property) => isZeroLength(get(property)));
  if (overflowHidden && zeroBox) return 'zero-size';
  if (/^scale\(\s*0\s*\)$/.test(get('transform') || '')) return 'zero-size';

  return null;
}

const RESHOW_CLASS = /^(?:(?:sm|md|lg|xl|2xl|min-\[[^\]]+\]):(?:block|flex|grid|inline|inline-block|inline-flex|inline-grid|table|table-row|table-cell|contents|flow-root|list-item)|d-(?:sm|md|lg|xl|xxl)-(?:block|flex|grid|inline|inline-block|inline-flex|table))$/;
const VISUALLY_HIDDEN_CLASSES = new Set(['sr-only', 'visually-hidden', 'visuallyhidden', 'screen-reader-text', 'screen-reader-only', 'a11y-hidden', 'element-invisible']);
const HIDING_CLASSES = new Set(['hidden', 'd-none', 'is-hidden', 'u-hidden', 'hide', 'display-none', 'hidden-xs-up']);

export function hiddenKindFromClasses(classAttribute) {
  const classes = String(classAttribute || '').split(/\s+/).filter(Boolean);
  if (classes.length === 0) return null;
  if (classes.some((name) => RESHOW_CLASS.test(name))) return null;
  if (classes.some((name) => VISUALLY_HIDDEN_CLASSES.has(name))) return 'visually-hidden';
  if (classes.some((name) => HIDING_CLASSES.has(name))) return 'hidden-class';
  if (classes.includes('invisible')) return 'visibility-hidden';
  return null;
}

const DYNAMIC_SELECTOR = /::|:(hover|focus|active|visited|focus-within|focus-visible|target|checked|placeholder-shown|before|after|first-line|first-letter)\b/i;

// Top-level rules only; conditional blocks such as @media are skipped because
// their conditions cannot be evaluated without a viewport.
export function extractHiddenRules(cssText) {
  const css = String(cssText || '').replace(/\/\*[\s\S]*?\*\//g, '');
  const rules = [];
  let index = 0;

  while (index < css.length) {
    const open = css.indexOf('{', index);
    if (open === -1) break;
    const prelude = css.slice(index, open).trim();

    let depth = 1;
    let cursor = open + 1;
    while (cursor < css.length && depth > 0) {
      if (css[cursor] === '{') depth += 1;
      if (css[cursor] === '}') depth -= 1;
      cursor += 1;
    }

    const body = css.slice(open + 1, cursor - 1);
    index = cursor;

    if (!prelude || prelude.startsWith('@')) continue;

    const kind = hiddenKindFromDeclarations(parseDeclarations(body));
    if (!kind) continue;

    for (const selector of prelude.split(',').map((item) => item.trim()).filter(Boolean)) {
      if (!DYNAMIC_SELECTOR.test(selector)) rules.push({ selector, kind });
    }
  }

  return rules;
}

export function hiddenKindForElement(element, stylesheetKinds) {
  const attribs = element.attribs || {};
  if (Object.prototype.hasOwnProperty.call(attribs, 'hidden')) return 'hidden-attribute';
  const inline = hiddenKindFromDeclarations(parseDeclarations(attribs.style));
  if (inline) return inline;
  if (stylesheetKinds?.has(element)) return stylesheetKinds.get(element);
  return hiddenKindFromClasses(attribs.class);
}
