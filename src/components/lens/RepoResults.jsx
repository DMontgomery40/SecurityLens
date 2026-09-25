import React from 'react';
import { SEVERITY_LABEL, SEVERITY_ORDER, INSTRUCTION_KINDS, topSeverity } from './model.js';

const anchorFor = (location) => `loc-${String(location || '').replace(/[^a-zA-Z0-9]+/g, '-')}`;

function focus(location) {
  const element = document.getElementById(anchorFor(location));
  if (!element) return;
  if (element.tagName === 'DETAILS') element.open = true;
  element.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

function Findings({ findings }) {
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  if (sorted.length === 0) {
    return (
      <p className="sl-support" style={{ margin: 0, padding: '0 22px 18px' }}>
        Nothing here tries to steer an agent.
      </p>
    );
  }
  return (
    <ul className="sl-findings">
      {sorted.map((finding) => (
        <li key={finding.id} className="sl-finding">
          <button type="button" onClick={() => focus(finding.location?.split(', ')[0])}>
            <span className={`sl-finding-bar sl-sevtext-${finding.severity}`} aria-hidden="true" />
            <span>
              <span className="sl-finding-title">
                <span className={`sl-sevtext-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}.</span> {finding.title}
              </span>
              <span className="sl-finding-detail" style={{ display: 'block' }}>
                {finding.location}
              </span>
              {finding.excerpt && <span className="sl-finding-excerpt" style={{ display: 'block', whiteSpace: 'pre-wrap' }}>{finding.excerpt}</span>}
              {finding.decoded && (
                <span className="sl-finding-detail" style={{ display: 'block' }}>
                  Decodes to: <strong style={{ color: 'var(--ink)' }}>{finding.decoded}</strong>
                </span>
              )}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function Segments({ segments, limit = 1200 }) {
  return segments.map((segment, index) => (
    <div key={index} className={`sl-block sl-block-${segment.zone}`} style={{ gridTemplateColumns: '120px minmax(0, 1fr)' }}>
      <div className="sl-speaker">
        <span className="sl-speaker-name">{segment.zone === 'voice' ? 'The repository' : segment.zone === 'hidden' ? 'Hidden' : 'Someone else'}</span>
        {segment.zone === 'hidden' && <span className="sl-speaker-basis">HTML comment</span>}
      </div>
      <p className="sl-passage" style={{ whiteSpace: 'pre-wrap' }}>
        {segment.text.length > limit ? `${segment.text.slice(0, limit)}…` : segment.text}
      </p>
    </div>
  ));
}

function Badge({ findings }) {
  if (!findings.length) return <span className="sl-small">Nothing flagged</span>;
  const severity = topSeverity(findings);
  return <span className={`sl-sev sl-sevtext-${severity}`}>{SEVERITY_LABEL[severity]}</span>;
}

export default function RepoResults({ report }) {
  const instructive = report.findings.filter((finding) => INSTRUCTION_KINDS.has(finding.kind) || finding.kind === 'instruction-file-risky-rule');
  const serious = instructive.filter((finding) => ['critical', 'high'].includes(finding.severity));
  const flaggedDiscussions = report.discussions.filter((item) => item.findings.length > 0);
  const cleanDiscussions = report.discussions.length - flaggedDiscussions.length;
  const servers = report.configs.flatMap((config) => config.servers.map((server) => ({ ...server, path: config.path })));
  const hooks = report.configs.flatMap((config) => config.hooks.map((hook) => ({ ...hook, path: config.path })));
  const coverage = report.coverage || {};

  return (
    <div className="sl-results">
      <div className="sl-stack" style={{ gap: 20 }}>
        <section className="sl-panel" aria-labelledby="repo-files-head">
          <div className="sl-page-meta">
            <h2 id="repo-files-head" className="sl-page-title">
              What {report.repo.owner}/{report.repo.name} tells agents
            </h2>
            <span className="sl-page-url">
              {report.instructionFiles.length === 0 ? 'No agent instruction files' : `${report.instructionFiles.length} instruction file${report.instructionFiles.length === 1 ? '' : 's'} on ${report.repo.defaultBranch}`}
            </span>
          </div>
          {report.instructionFiles.length === 0 ? (
            <p className="sl-support" style={{ margin: 0, padding: '16px 22px' }}>
              This repository has no AGENTS.md, CLAUDE.md, rules files, or skills, so agents only get what users and issues tell them.
            </p>
          ) : (
            report.instructionFiles.map((file) => (
              <details key={file.path} id={anchorFor(file.path)} open={file.findings.length > 0} style={{ borderTop: '1px solid var(--rule)' }}>
                <summary style={{ padding: '12px 22px', cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span className="sl-inline-code">{file.path}</span>
                  <Badge findings={file.findings} />
                </summary>
                <Segments segments={file.segments} />
              </details>
            ))
          )}
        </section>

        <section className="sl-panel" aria-labelledby="repo-discussions-head">
          <div className="sl-page-meta">
            <h2 id="repo-discussions-head" className="sl-page-title">
              What other people say to agents here
            </h2>
            <span className="sl-page-url">
              {coverage.issuesRead ?? 0} open issues and pull requests, {coverage.commentsRead ?? 0} recent comments
            </span>
          </div>
          {flaggedDiscussions.map((item) => (
            <details key={item.number} open style={{ borderTop: '1px solid var(--rule)' }} id={anchorFor(`${item.isPullRequest ? 'Pull request' : 'Issue'} #${item.number}`)}>
              <summary style={{ padding: '12px 22px', cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <strong>#{item.number}</strong> <span>{item.title || 'Comments'}</span> <Badge findings={item.findings} />
              </summary>
              <div id={anchorFor(`Comment on #${item.number}`)} style={{ padding: '0 22px 14px' }}>
                {item.findings.map((finding, index) => (
                  <p key={index} className={`sl-passage sl-passage-flagged sl-sev-${finding.severity}`} style={{ margin: '0 10px 8px' }}>
                    <span className={`sl-flag sl-sevtext-${finding.severity}`}>
                      <span className="sl-sev">{SEVERITY_LABEL[finding.severity]}</span>
                      <span>
                        {finding.title}, {finding.location}
                      </span>
                    </span>
                    <br />
                    {finding.excerpt}
                  </p>
                ))}
                {item.url && (
                  <a href={item.url} rel="noreferrer noopener" target="_blank">
                    Open on GitHub
                  </a>
                )}
              </div>
            </details>
          ))}
          <p className="sl-support" style={{ margin: 0, padding: '14px 22px', borderTop: flaggedDiscussions.length ? '1px solid var(--rule)' : 'none' }}>
            {cleanDiscussions === 0 && flaggedDiscussions.length === 0
              ? 'No open issues or recent comments.'
              : `${cleanDiscussions} ${cleanDiscussions === 1 ? 'thread has' : 'threads have'} nothing aimed at agents.`}
          </p>
        </section>
      </div>

      <aside className="sl-verdict" aria-label="Verdict">
        <section className="sl-panel sl-panel-pad">
          <h2 className="sl-verdict-line">
            {serious.length === 0
              ? 'Nothing here gives agents dangerous orders.'
              : `${serious.length} place${serious.length === 1 ? '' : 's'} give${serious.length === 1 ? 's' : ''} agents orders the maintainers may not know about.`}
          </h2>
          <p className="sl-support" style={{ margin: 0 }}>
            Agents treat instruction files as the repository speaking. Issues, pull requests, and comments are other people.
          </p>
        </section>
        <section className="sl-panel">
          <div className="sl-panel-head">
            <h2 className="sl-h3" style={{ margin: 0 }}>
              Findings
            </h2>
            <span className="sl-small">{report.findings.filter((finding) => finding.severity !== 'info').length || 'None'}</span>
          </div>
          <Findings findings={report.findings} />
        </section>
        {(servers.length > 0 || hooks.length > 0) && (
          <section className="sl-panel sl-panel-pad">
            <h2 className="sl-h3">Automation offered to agents</h2>
            <ul className="sl-notes" style={{ color: 'var(--ink)' }}>
              {servers.map((server) => (
                <li key={`${server.path}-${server.name}`}>
                  MCP server <span className="sl-inline-code">{server.name}</span>: <span className="sl-mono" style={{ fontSize: 13 }}>{server.command || server.url}</span>
                </li>
              ))}
              {hooks.map((hook, index) => (
                <li key={`${hook.path}-${index}`}>
                  {hook.event} hook: <span className="sl-mono" style={{ fontSize: 13 }}>{hook.command}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        <section className="sl-panel sl-panel-pad">
          <h2 className="sl-h3">What the lens read</h2>
          <ul className="sl-notes">
            <li>
              {coverage.filesRead ?? 0} of {coverage.filesMatched ?? 0} agent files on {report.repo.defaultBranch}.
            </li>
            {coverage.filesSkippedTooLarge > 0 && <li>{coverage.filesSkippedTooLarge} file(s) over 256 KB were skipped.</li>}
            {coverage.treeTruncated && <li>GitHub truncated the file list, so deep files may be missing.</li>}
            <li>The {coverage.issuesRead ?? 0} most recently updated open issues and pull requests, and the {coverage.commentsRead ?? 0} most recent comments.</li>
            {coverage.rateLimitRemaining !== null && coverage.rateLimitRemaining !== undefined && (
              <li>
                {coverage.rateLimitRemaining} GitHub API requests left this hour{coverage.authenticated ? '' : ' without a token'}.
              </li>
            )}
          </ul>
        </section>
      </aside>
    </div>
  );
}
