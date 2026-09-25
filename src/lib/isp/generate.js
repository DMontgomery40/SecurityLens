// Turns an analysis report into a policy and ready-to-paste delivery snippets.

import { parsePolicy, serializePolicy, POLICY_HEADER, emptyDirectives } from './policy.js';

const escapeHtmlAttribute = (value) => value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escapeDoubleQuoted = (value) => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
const escapeSingleQuoted = (value) => value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

export function candidateRegions(report) {
  return (report?.regions || []).filter((region) => region.zone === 'untrusted' && (region.basis === 'inferred' || region.basis === 'embed') && region.suggestedSelector);
}

// options:
//   include       region ids to declare untrusted (default: every candidate)
//   defaultZone   'voice' or 'untrusted'
//   voice         voice selectors, used with defaultZone 'untrusted'
//   untrusted     extra untrusted selectors
//   tools, instructions, reportTo  override the matching directives
export function generatePolicy(report, options = {}) {
  const existing = report?.policy?.present ? report.policy.directives : emptyDirectives();
  const candidates = candidateRegions(report);
  const included = Array.isArray(options.include) ? candidates.filter((region) => options.include.includes(region.id)) : candidates;

  const untrusted = unique([...existing.untrusted, ...included.map((region) => region.suggestedSelector), ...(options.untrusted || [])]);
  const defaultZone = options.defaultZone || existing.default || 'voice';
  const voice = defaultZone === 'untrusted' ? unique([...(options.voice || existing.voice || [])]) : [];

  const hasTools = (report?.tools?.declarative?.length || 0) + (report?.tools?.imperative?.length || 0) > 0;
  let tools = existing.tools;
  if (options.tools !== undefined) tools = options.tools;
  else if (tools === null && hasTools) tools = ["'self'"];

  const directives = {
    default: defaultZone,
    voice,
    untrusted,
    tools: tools && tools.length ? tools : null,
    instructions: options.instructions !== undefined ? options.instructions || null : existing.instructions,
    reportTo: options.reportTo !== undefined ? options.reportTo || null : existing.reportTo
  };

  const policy = serializePolicy(directives);
  const check = parsePolicy(policy);

  return {
    directives: check.directives,
    policy,
    check: { errors: check.errors, warnings: check.warnings, failedClosed: check.failedClosed },
    header: `${POLICY_HEADER}: ${policy}`,
    meta: `<meta http-equiv="${POLICY_HEADER}" content="${escapeHtmlAttribute(policy)}">`,
    wellKnown: `${policy}\n`,
    snippets: {
      netlify: `/*\n  ${POLICY_HEADER}: ${policy}`,
      nginx: `add_header ${POLICY_HEADER} "${escapeDoubleQuoted(policy)}" always;`,
      apache: `Header always set ${POLICY_HEADER} "${escapeDoubleQuoted(policy)}"`,
      express: `res.setHeader('${POLICY_HEADER}', '${escapeSingleQuoted(policy)}');`
    },
    regions: included.map(({ id, label, reason, suggestedSelector, textLength }) => ({ id, label, reason, selector: suggestedSelector, textLength }))
  };
}
