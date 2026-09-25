import React from 'react';
import { Link } from 'react-router-dom';
import { INSTRUCTION_KINDS, SEVERITY_LABEL, SEVERITY_ORDER, speakerShares } from './model.js';

function focusSegment(segmentId) {
  const element = document.getElementById(`seg-${segmentId}`);
  if (!element) return;
  element.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
  element.classList.remove('sl-passage-target');
  void element.offsetWidth;
  element.classList.add('sl-passage-target');
  element.focus({ preventScroll: true });
}

function verdictSentence(report) {
  const instructive = report.findings.filter((finding) => INSTRUCTION_KINDS.has(finding.kind) && ['critical', 'high', 'medium'].includes(finding.severity));
  const uncontained = instructive.filter((finding) => !finding.contained);
  if (instructive.length === 0) return 'Nothing on this page tells agents what to do.';
  const count = instructive.length;
  const base = `${count} passage${count === 1 ? '' : 's'} ${count === 1 ? 'tells' : 'tell'} agents what to do.`;
  if (uncontained.length === 0) return `${base} The policy marks ${count === 1 ? 'it' : 'them'} as someone else speaking.`;
  return base;
}

function SpeakerBar({ report }) {
  const shares = speakerShares(report);
  const rows = [
    { key: 'voice', label: 'The site', color: 'var(--voice)', value: shares.voice },
    { key: 'untrusted', label: 'Other people', color: 'var(--untrusted-bar)', value: shares.untrusted },
    { key: 'hidden', label: 'Hidden', color: 'var(--hidden)', value: shares.hidden }
  ];
  return (
    <>
      <div className="sl-speakerbar" role="img" aria-label={rows.map((row) => `${row.label} ${row.value}%`).join(', ')}>
        {rows.map((row) => (row.value > 0 ? <span key={row.key} style={{ width: `${row.value}%`, background: row.color }} /> : null))}
      </div>
      <ul className="sl-legend">
        {rows.map((row) => (
          <li key={row.key}>
            <span className="sl-swatch" style={{ background: row.color }} aria-hidden="true" />
            {row.label}
            <span className="sl-legend-value">{row.value}%</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function FindingItem({ finding }) {
  const body = (
    <>
      <span className={`sl-finding-bar sl-sevtext-${finding.severity}`} aria-hidden="true" />
      <span>
        <span className="sl-finding-title">
          <span className={`sl-sevtext-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}.</span> {finding.title}
        </span>
        {finding.detail && <span className="sl-finding-detail" style={{ display: 'block' }}>{finding.detail}</span>}
        {finding.excerpt && <span className="sl-finding-excerpt" style={{ display: 'block' }}>{finding.excerpt}</span>}
      </span>
    </>
  );
  return (
    <li className="sl-finding">
      {finding.segmentId ? (
        <button type="button" onClick={() => focusSegment(finding.segmentId)}>
          {body}
        </button>
      ) : (
        <div className="sl-finding-static">{body}</div>
      )}
    </li>
  );
}

const SOURCE_NAME = { header: 'the response header', meta: 'a meta tag in head', 'well-known': 'the site’s well-known file' };

function PolicyStatus({ report }) {
  const policy = report.policy;
  if (!policy.present) {
    return (
      <section className="sl-panel sl-panel-pad" aria-labelledby="policy-status">
        <h2 id="policy-status" className="sl-h3">
          No Instruction Security Policy
        </h2>
        <p className="sl-support" style={{ margin: '0 0 14px' }}>
          Agents have to guess who is speaking here. The zones above are the lens's best inference.
        </p>
        <Link to="/policy" className="sl-button" style={{ textDecoration: 'none' }}>
          Write a policy for this page
        </Link>
      </section>
    );
  }
  const errors = policy.errors.length;
  return (
    <section className="sl-panel sl-panel-pad" aria-labelledby="policy-status">
      <h2 id="policy-status" className="sl-h3">
        Policy from {SOURCE_NAME[policy.source] || policy.source}
      </h2>
      {policy.failedClosed && (
        <p className="sl-message sl-message-error" style={{ margin: '0 0 12px' }}>
          The policy has errors, so agents ignore every voice grant in it.
        </p>
      )}
      <pre className="sl-code" style={{ marginBottom: 12 }}>
        <code>{policy.serialized}</code>
      </pre>
      <p className="sl-small" style={{ margin: '0 0 12px' }}>
        {errors === 0 ? 'The policy parses cleanly.' : `${errors} error${errors === 1 ? '' : 's'} in the policy.`}
      </p>
      <Link to="/policy" className="sl-button sl-button-quiet sl-button-small" style={{ textDecoration: 'none' }}>
        Improve this policy
      </Link>
    </section>
  );
}

function Coverage({ report }) {
  const notes = [];
  const fetchInfo = report.fetch;
  if (fetchInfo) {
    notes.push(`Fetched ${fetchInfo.finalUrl} (HTTP ${fetchInfo.status}).`);
    if (fetchInfo.redirects?.length) notes.push(`Followed ${fetchInfo.redirects.length} redirect${fetchInfo.redirects.length === 1 ? '' : 's'}.`);
    if (fetchInfo.policyOverride) notes.push('Analyzed with a draft policy instead of the site’s own.');
  } else if (report.coverage?.source === 'pasted-html' || report.coverage?.source === 'demo') {
    notes.push('Analyzed in your browser. Nothing was uploaded.');
  }
  if (report.coverage?.likelyScriptRendered) notes.push('Most of this page is built by JavaScript, which the lens does not run. Paste the rendered HTML to see it.');
  else if (report.coverage?.scriptsNotExecuted) notes.push('Scripts were not run, so anything JavaScript adds later is missing.');
  const frames = report.coverage?.frames?.filter((frame) => frame.crossOrigin).length || 0;
  if (frames) notes.push(`${frames} embedded frame${frames === 1 ? '' : 's'} from other sites ${frames === 1 ? 'was' : 'were'} not read.`);
  if (report.coverage?.truncated) notes.push('The page was too long to read in full.');

  return (
    <section className="sl-panel sl-panel-pad" aria-labelledby="coverage-head">
      <h2 id="coverage-head" className="sl-h3">
        What the lens read
      </h2>
      <ul className="sl-notes">
        {notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </section>
  );
}

function Tools({ report }) {
  const tools = [...(report.tools?.declarative || []), ...(report.tools?.imperative || [])];
  if (tools.length === 0) return null;
  return (
    <section className="sl-panel sl-panel-pad" aria-labelledby="tools-head">
      <h2 id="tools-head" className="sl-h3">
        Agent tools on this page
      </h2>
      <ul className="sl-notes" style={{ color: 'var(--ink)' }}>
        {tools.map((tool, index) => (
          <li key={`${tool.name}-${index}`}>
            <span className="sl-inline-code">{tool.name || 'unnamed tool'}</span>{' '}
            <span className="sl-small">
              {tool.kind === 'declarative' ? 'form tool' : 'script tool'}
              {tool.allowed === false ? ', not allowed by the policy' : tool.allowed === true ? ', allowed by the policy' : ''}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function VerdictPanel({ report }) {
  const serious = report.findings.filter((finding) => finding.severity !== 'info');
  const notes = report.findings.filter((finding) => finding.severity === 'info' && finding.kind !== 'no-policy');
  const sorted = [...serious].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  return (
    <aside className="sl-verdict" aria-label="Verdict">
      <section className="sl-panel sl-panel-pad" aria-labelledby="verdict-head">
        <h2 id="verdict-head" className="sl-verdict-line">
          {verdictSentence(report)}
        </h2>
        <SpeakerBar report={report} />
      </section>

      <section className="sl-panel" aria-labelledby="findings-head">
        <div className="sl-panel-head">
          <h2 id="findings-head" className="sl-h3" style={{ margin: 0 }}>
            Findings
          </h2>
          <span className="sl-small">{serious.length === 0 ? 'None' : `${serious.length}`}</span>
        </div>
        {sorted.length > 0 ? (
          <ul className="sl-findings">
            {sorted.map((finding) => (
              <FindingItem key={finding.id} finding={finding} />
            ))}
          </ul>
        ) : (
          <p className="sl-support" style={{ margin: 0, padding: '0 22px 18px' }}>
            No text on this page tries to steer an agent.
          </p>
        )}
        {notes.length > 0 && (
          <ul className="sl-findings">
            {notes.map((finding) => (
              <FindingItem key={finding.id} finding={finding} />
            ))}
          </ul>
        )}
      </section>

      <PolicyStatus report={report} />
      <Tools report={report} />
      <Coverage report={report} />
    </aside>
  );
}
