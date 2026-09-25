// CLI commands for the Instruction Security Policy lens and the MCP server.

import { readFile } from 'fs/promises';
import chalk from 'chalk';
import { analyzeDocument } from '../lib/isp/analyze.js';
import { toAgentView } from '../lib/isp/agentView.js';
import { generatePolicy } from '../lib/isp/generate.js';
import { parsePolicy, serializePolicy } from '../lib/isp/policy.js';
import { lensUrl, lensRepository, isRepositoryUrl } from '../lib/isp/node/lens.js';
import { FetchError } from '../lib/isp/node/safeFetch.js';
import { createLensMcpServer, explainPolicy } from '../lib/isp/node/mcpServer.js';

const SEVERITY_COLOR = { critical: chalk.red.bold, high: chalk.red, medium: chalk.yellow, low: chalk.white, info: chalk.cyan };
const ZONE_LABEL = { voice: chalk.blue.bold('The site'), untrusted: chalk.yellow.bold('Someone else'), hidden: chalk.magenta.bold('Hidden') };

function write(text = '') {
  process.stdout.write(`${text}\n`);
}

async function loadReport(target, options) {
  if (options.html) {
    const html = await readFile(options.html, 'utf8');
    const headers = options.policy ? { 'instruction-security-policy': options.policy } : {};
    return analyzeDocument({ html, url: target || null, headers, source: 'pasted-html' });
  }
  if (!target) throw new FetchError('missing-input', 'Give a URL, or --html <file>.', 400);
  return lensUrl(target, { policyOverride: options.policy ?? null });
}

function printTranscript(report) {
  write(chalk.bold(report.title || report.url || 'Page'));
  if (report.url) write(chalk.gray(report.url));
  write(report.policy.present ? `Policy from the ${report.policy.source}: ${report.policy.serialized}` : 'No Instruction Security Policy. Speakers are inferred.');
  write();

  const regions = new Map(report.regions.map((region) => [region.id, region]));
  let lastKey = null;
  for (const segment of report.segments) {
    const key = segment.zone === 'voice' ? 'voice' : `${segment.zone}:${segment.regionId}`;
    if (key !== lastKey) {
      const region = regions.get(segment.regionId);
      const detail = segment.zone === 'hidden' ? region?.reason : segment.zone === 'untrusted' ? region?.label : null;
      write(`${ZONE_LABEL[segment.zone]}${detail ? chalk.gray(` (${detail})`) : ''}`);
      lastKey = key;
    }
    write(`  ${segment.text.length > 400 ? `${segment.text.slice(0, 400)}…` : segment.text}`);
  }

  write();
  const findings = report.findings.filter((finding) => finding.severity !== 'info');
  write(chalk.bold(findings.length ? `${findings.length} finding${findings.length === 1 ? '' : 's'}` : 'No findings above informational'));
  for (const finding of findings) {
    write(`  ${SEVERITY_COLOR[finding.severity](finding.severity.toUpperCase())} ${finding.title}${finding.contained ? chalk.gray(' (contained by policy)') : ''}`);
    if (finding.excerpt) write(chalk.gray(`    ${finding.excerpt}`));
    if (finding.decoded) write(chalk.gray(`    decodes to: ${finding.decoded}`));
  }
  if (report.coverage.scriptsNotExecuted) write(chalk.gray('\nScripts were not run, so content that JavaScript adds is missing.'));
}

function printRepository(report) {
  write(chalk.bold(`${report.repo.owner}/${report.repo.name}`));
  write(`${report.instructionFiles.length} agent instruction files, ${report.summary.discussions} issue and pull request threads, ${report.summary.comments} recent comments.`);
  for (const config of report.configs) {
    for (const server of config.servers) write(`MCP server ${server.name}: ${server.command || server.url} ${chalk.gray(`(${config.path})`)}`);
    for (const hook of config.hooks) write(`${hook.event} hook: ${hook.command} ${chalk.gray(`(${config.path})`)}`);
  }
  write();
  const findings = report.findings.filter((finding) => finding.severity !== 'info');
  write(chalk.bold(findings.length ? `${findings.length} finding${findings.length === 1 ? '' : 's'}` : 'No findings above informational'));
  for (const finding of findings) {
    write(`  ${SEVERITY_COLOR[finding.severity](finding.severity.toUpperCase())} ${finding.title} ${chalk.gray(`(${finding.location})`)}`);
    if (finding.excerpt) write(chalk.gray(`    ${finding.excerpt}`));
  }
}

function exitCodeFor(report) {
  return report.findings.some((finding) => ['critical', 'high'].includes(finding.severity) && !finding.contained) ? 1 : 0;
}

export function registerIspCommands(program) {
  program
    .command('lens')
    .description('Show who is speaking on a web page and flag text aimed at AI agents')
    .argument('[url]', 'Public page URL, or a GitHub repository URL')
    .option('--html <file>', 'Analyze a local HTML file instead of fetching')
    .option('--policy <policy>', 'Apply a draft Instruction Security Policy')
    .option('-f, --format <format>', 'transcript, agent, or json', 'transcript')
    .action(async (url, options) => {
      try {
        if (url && !options.html && isRepositoryUrl(url)) {
          const repoReport = await lensRepository(url, { token: process.env.GITHUB_TOKEN || null });
          if (options.format === 'json') write(JSON.stringify(repoReport, null, 2));
          else printRepository(repoReport);
          process.exitCode = exitCodeFor(repoReport);
          return;
        }
        const report = await loadReport(url, options);
        if (options.format === 'json') write(JSON.stringify(report, null, 2));
        else if (options.format === 'agent') write(toAgentView(report).text);
        else printTranscript(report);
        process.exitCode = exitCodeFor(report);
      } catch (error) {
        process.stderr.write(`${chalk.red('Error:')} ${error.message}\n`);
        process.exitCode = 2;
      }
    });

  const policy = program.command('policy').description('Check or write an Instruction Security Policy');

  policy
    .command('check')
    .description('Parse a policy and explain it')
    .argument('<policy>', 'Header value, for example "untrusted #comments"')
    .action((value) => {
      const parsed = parsePolicy(value);
      for (const item of parsed.errors) write(`${chalk.red('error')} ${item.message}`);
      for (const item of parsed.warnings) write(`${chalk.yellow('warning')} ${item.message}`);
      if (parsed.failedClosed) write(chalk.red('Fails closed: agents ignore every voice grant.'));
      for (const line of explainPolicy(parsed)) write(line);
      write(`Normalized: ${serializePolicy(parsed.directives)}`);
      process.exitCode = parsed.errors.length ? 1 : 0;
    });

  policy
    .command('write')
    .description('Draft a policy from the user content on a page')
    .argument('[url]', 'Public page URL')
    .option('--html <file>', 'Analyze a local HTML file instead of fetching')
    .option('--default <zone>', 'voice or untrusted', 'voice')
    .option('--voice <selectors>', 'Comma-separated voice selectors, used with --default untrusted')
    .option('--report-to <url>', 'Absolute https URL for violation reports')
    .action(async (url, options) => {
      try {
        const report = await loadReport(url, options);
        const generated = generatePolicy(report, {
          defaultZone: options.default,
          voice: options.voice ? options.voice.split(',').map((item) => item.trim()).filter(Boolean) : undefined,
          reportTo: options.reportTo
        });
        write(generated.header);
        for (const item of generated.check.warnings) write(`${chalk.yellow('warning')} ${item.message}`);
      } catch (error) {
        process.stderr.write(`${chalk.red('Error:')} ${error.message}\n`);
        process.exitCode = 2;
      }
    });

  program
    .command('mcp')
    .description('Run the SecurityLens MCP server over stdio')
    .action(async () => {
      const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
      const server = createLensMcpServer();
      await server.connect(new StdioServerTransport());
    });
}
