// Discovery of agent tools a page exposes through WebMCP, declaratively with
// form attributes or imperatively through navigator.modelContext.

export function originOf(value, base) {
  try {
    const url = new URL(value, base || undefined);
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : null;
  } catch {
    return null;
  }
}

export function isOriginAllowed(origin, toolsDirective, pageOrigin) {
  if (!Array.isArray(toolsDirective)) return null;
  if (toolsDirective.includes("'none'")) return false;
  if (!origin) return false;
  if (toolsDirective.includes("'self'") && pageOrigin && origin === pageOrigin) return true;

  return toolsDirective.some((source) => {
    if (source === origin) return true;
    const wildcard = source.match(/^(https?):\/\/\*\.(.+)$/);
    if (!wildcard) return false;
    try {
      const url = new URL(origin);
      return url.protocol === `${wildcard[1]}:` && url.host.endsWith(`.${wildcard[2]}`);
    } catch {
      return false;
    }
  });
}

export function findDeclarativeTools($, pageOrigin, toolsDirective) {
  const tools = [];

  $('form[toolname]').each((_index, form) => {
    const $form = $(form);
    const params = [];

    $form.find('input[name], select[name], textarea[name]').each((_i, field) => {
      const $field = $(field);
      if (($field.attr('type') || '').toLowerCase() === 'hidden' && !$field.attr('toolparamdescription')) return;
      params.push({
        name: $field.attr('name'),
        description: $field.attr('toolparamdescription') || '',
        type: field.name === 'input' ? ($field.attr('type') || 'text').toLowerCase() : field.name,
        required: $field.attr('required') !== undefined
      });
    });

    tools.push({
      kind: 'declarative',
      name: $form.attr('toolname'),
      description: $form.attr('tooldescription') || '',
      autosubmit: $form.attr('toolautosubmit') !== undefined,
      params,
      origin: pageOrigin,
      allowed: isOriginAllowed(pageOrigin, toolsDirective, pageOrigin)
    });
  });

  return tools;
}

const STRING_FIELD = (field) => new RegExp(`\\b${field}\\s*:\\s*(['"\`])((?:\\\\.|(?!\\1)[\\s\\S]){0,1500}?)\\1`, 'g');

export function findImperativeTools(inlineScripts, pageOrigin, toolsDirective) {
  const tools = [];

  for (const script of inlineScripts) {
    if (!/navigator\s*\.\s*modelContext/.test(script) && !/modelContext\s*\.\s*(registerTool|provideContext)/.test(script)) continue;

    const calls = [...script.matchAll(/\b(registerTool|provideContext)\s*\(/g)];
    for (const call of calls) {
      const region = script.slice(call.index, call.index + 4000);
      const names = [...region.matchAll(STRING_FIELD('name'))].map((match) => match[2]);
      const descriptions = [...region.matchAll(STRING_FIELD('description'))].map((match) => match[2]);
      const count = call[1] === 'registerTool' ? Math.min(1, Math.max(names.length, 1)) : Math.max(names.length, 1);

      for (let index = 0; index < count; index += 1) {
        tools.push({
          kind: 'imperative',
          via: call[1],
          name: names[index] || null,
          description: descriptions[index] || '',
          params: [],
          origin: pageOrigin,
          allowed: isOriginAllowed(pageOrigin, toolsDirective, pageOrigin)
        });
      }
    }
  }

  return tools;
}
