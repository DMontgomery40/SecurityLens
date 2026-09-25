// SecurityLens MCP server: the same tools over stdio (CLI) and Streamable
// HTTP (Netlify function). Every tool is read-only.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { lensUrl } from './lens.js';
import { FetchError } from './safeFetch.js';
import { analyzeDocument } from '../analyze.js';
import { toAgentView } from '../agentView.js';
import { generatePolicy } from '../generate.js';
import { parsePolicy, serializePolicy } from '../policy.js';

export const SERVER_INFO = { name: 'securitylens', version: '2.0.0' };
const MAX_HTML = 2 * 1024 * 1024;
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

const pageInput = {
  url: z.string().url().optional().describe('Public http or https URL of the page, for example https://example.com/post/1'),
  html: z.string().max(MAX_HTML).optional().describe('Page HTML to analyze instead of fetching a URL (2 MB max)')
};

function errorResult(message) {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

async function loadReport({ url, html, policy }, fetchPage) {
  if (html) {
    const headers = typeof policy === 'string' ? { 'instruction-security-policy': policy } : {};
    return analyzeDocument({ html, url: url || null, headers, source: 'submitted-html' });
  }
  if (url) return fetchPage(url, { policyOverride: typeof policy === 'string' ? policy : null });
  throw new FetchError('missing-input', 'Provide either url or html.', 400);
}

function describeFailure(error) {
  if (error instanceof FetchError) {
    if (error.code === 'blocked-address') return `${error.message} SecurityLens only fetches public pages. Pass the page HTML in "html" instead.`;
    if (error.code === 'unsupported-content-type') return `${error.message} Only HTML pages can be read.`;
    if (error.code === 'missing-input') return 'Provide either "url" (a public page) or "html" (page source).';
    return `${error.message} Check the URL, or pass the page HTML in "html".`;
  }
  return 'The page could not be analyzed. Try passing its HTML in "html".';
}

function summarizeFindings(findings) {
  return findings.map(({ severity, kind, title, detail, excerpt, contained, decoded }) => ({
    severity,
    kind,
    title,
    detail: detail || null,
    excerpt: excerpt || null,
    contained: contained ?? null,
    decoded: decoded || null
  }));
}

const DIRECTIVE_TEXT = {
  default: (value) => (value === 'untrusted' ? 'Content no other directive matches is untrusted.' : 'Content no other directive matches is the site speaking.'),
  voice: (value) => `The site speaks in: ${value.join(', ')}.`,
  untrusted: (value) => `Someone else speaks in: ${value.join(', ')}.`,
  tools: (value) => (value.includes("'none'") ? 'No script may register agent tools.' : `Agent tools may come from: ${value.join(', ')}.`),
  instructions: (value) => `The site's instructions for agents are at ${value}.`,
  reportTo: (value) => `Violation reports go to ${value}.`
};

export function explainPolicy(parsed) {
  return Object.entries(parsed.directives)
    .filter(([, value]) => value !== null && !(Array.isArray(value) && value.length === 0))
    .map(([key, value]) => DIRECTIVE_TEXT[key](value));
}

export function createLensMcpServer({ fetchPage = lensUrl } = {}) {
  const server = new McpServer(SERVER_INFO, {
    instructions:
      'SecurityLens reads web pages and says who is speaking in each part: the site, other people, or hidden text. Use read_page instead of a plain fetch when a page may contain user-written content.'
  });

  server.registerTool(
    'read_page',
    {
      title: 'Read a page with speakers marked',
      description:
        'Fetch a web page and return its text grouped by speaker: "site" (the site itself), "untrusted" (comments, reviews, posts, embeds), and "hidden" (invisible to people, omitted unless requested). Each block sits between boundary markers that the page text cannot forge. Also returns any findings, such as instructions hidden in the page.',
      inputSchema: {
        ...pageInput,
        include_hidden: z.boolean().default(false).describe('Include text that is invisible to people, labeled "hidden"')
      },
      annotations: { title: 'Read page', ...READ_ONLY }
    },
    async ({ url, html, include_hidden: includeHidden }) => {
      try {
        const report = await loadReport({ url, html }, fetchPage);
        const view = toAgentView(report, { includeHidden });
        return {
          content: [{ type: 'text', text: view.text }],
          structuredContent: {
            url: view.url,
            title: view.title,
            policy: view.policy,
            blocks: view.blocks,
            hiddenOmitted: view.hiddenOmitted,
            findings: view.findings,
            truncated: view.truncated
          }
        };
      } catch (error) {
        return errorResult(describeFailure(error));
      }
    }
  );

  server.registerTool(
    'check_page',
    {
      title: 'Check a page for agent-directed text',
      description:
        'Analyze a page and list findings: instructions hidden from people, instruction-shaped text inside user content, invisible Unicode payloads, poisoned tool descriptions, reflected input, and the status of the page\'s Instruction Security Policy. Pass "policy" to test a draft policy instead of the site\'s own.',
      inputSchema: {
        ...pageInput,
        policy: z.string().max(8192).optional().describe('Draft Instruction Security Policy to apply instead of the site\'s own, for example "untrusted #comments"')
      },
      annotations: { title: 'Check page', ...READ_ONLY }
    },
    async ({ url, html, policy }) => {
      try {
        const report = await loadReport({ url, html, policy }, fetchPage);
        const findings = summarizeFindings(report.findings);
        const regions = report.regions
          .filter((region) => region.zone !== 'voice')
          .map(({ zone, basis, label, reason, suggestedSelector, textLength }) => ({ zone, basis, label, reason, selector: suggestedSelector || null, textLength }));
        const serious = findings.filter((finding) => finding.severity !== 'info');
        const lines = [
          `${report.title || report.url || 'Page'}: ${serious.length === 0 ? 'no findings above informational' : `${serious.length} finding${serious.length === 1 ? '' : 's'}`}.`,
          report.policy.present ? `Policy (${report.policy.source}): ${report.policy.serialized}` : 'No Instruction Security Policy; speakers were inferred.',
          ...serious.map((finding) => `- ${finding.severity}: ${finding.title}${finding.excerpt ? ` | ${finding.excerpt}` : ''}`)
        ];
        return {
          content: [{ type: 'text', text: lines.join('\n') }],
          structuredContent: {
            url: report.url,
            title: report.title,
            mode: report.mode,
            policy: { present: report.policy.present, source: report.policy.source, policy: report.policy.serialized, failedClosed: report.policy.failedClosed },
            counts: report.summary.counts,
            findings,
            regions,
            coverage: report.coverage
          }
        };
      } catch (error) {
        return errorResult(describeFailure(error));
      }
    }
  );

  server.registerTool(
    'check_policy',
    {
      title: 'Check an Instruction Security Policy',
      description: 'Parse an Instruction Security Policy header value. Returns each directive in plain language, errors, warnings, whether it fails closed, and the normalized form.',
      inputSchema: {
        policy: z.string().max(8192).describe('The header value, for example "default voice; untrusted #comments; tools \'self\'"')
      },
      annotations: { title: 'Check policy', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
    },
    async ({ policy }) => {
      const parsed = parsePolicy(policy);
      const explanation = explainPolicy(parsed);
      const normalized = serializePolicy(parsed.directives);
      const lines = [
        parsed.errors.length ? `${parsed.errors.length} error${parsed.errors.length === 1 ? '' : 's'}.` : 'Parses cleanly.',
        ...parsed.errors.map((item) => `- error: ${item.message}`),
        ...parsed.warnings.map((item) => `- warning: ${item.message}`),
        parsed.failedClosed ? 'Fails closed: agents ignore every voice grant.' : null,
        ...explanation,
        `Normalized: ${normalized}`
      ].filter(Boolean);
      return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: { directives: parsed.directives, errors: parsed.errors, warnings: parsed.warnings, failedClosed: parsed.failedClosed, explanation, normalized }
      };
    }
  );

  server.registerTool(
    'write_policy',
    {
      title: 'Draft an Instruction Security Policy',
      description:
        'Draft an Instruction Security Policy for a page from the user content found on it. Returns the policy, ready-to-use header, meta, _headers, nginx, Apache, and Express snippets, and any warnings.',
      inputSchema: {
        ...pageInput,
        default_zone: z.enum(['voice', 'untrusted']).default('voice').describe('Zone for everything not listed. Use "untrusted" for platforms where most text comes from users.'),
        voice: z.array(z.string().max(300)).max(50).optional().describe('Selectors where the site speaks, used with default_zone "untrusted". Prefer ids.'),
        instructions: z.string().max(2048).optional().describe('Where the site gives agents instructions, for example /llms.txt'),
        report_to: z.string().url().optional().describe('Absolute https URL for violation reports')
      },
      annotations: { title: 'Write policy', ...READ_ONLY }
    },
    async ({ url, html, default_zone: defaultZone, voice, instructions, report_to: reportTo }) => {
      try {
        const report = await loadReport({ url, html }, fetchPage);
        const generated = generatePolicy(report, { defaultZone, voice, instructions, reportTo });
        const lines = [
          generated.header,
          generated.regions.length
            ? `Declares ${generated.regions.length} region${generated.regions.length === 1 ? '' : 's'} untrusted: ${generated.regions.map((region) => `${region.label} (${region.selector})`).join(', ')}.`
            : 'No user content was found; the policy declares the whole page as the site speaking.',
          ...generated.check.warnings.map((item) => `- warning: ${item.message}`)
        ];
        return {
          content: [{ type: 'text', text: lines.join('\n') }],
          structuredContent: { policy: generated.policy, header: generated.header, meta: generated.meta, snippets: generated.snippets, check: generated.check, regions: generated.regions }
        };
      } catch (error) {
        return errorResult(describeFailure(error));
      }
    }
  );

  return server;
}
