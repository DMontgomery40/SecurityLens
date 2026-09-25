import React, { useCallback, useMemo, useRef, useState } from 'react';
import { SAMPLE_FILES } from '../lib/rearview/samples.js';
import { SEVERITY_LABEL } from '../components/lens/model.js';

const HARNESS_NAME = { 'claude-code': 'Claude Code', codex: 'Codex' };
const KIND_GROUPS = [
  ['action-after-injection', 'Did what untrusted content said'],
  ['action-after-untrusted', 'Acted right after untrusted instructions'],
  ['injection-seen', 'Read instructions in untrusted content'],
  ['secret-in-context', 'Secrets sent to the model'],
  ['secret-file', 'Secret files read'],
  ['risky-command', 'Risky commands']
];
const MAX_FILES = 3000;

function formatDate(value) {
  if (!value) return 'Unknown date';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown date' : date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function formatBytes(bytes) {
  if (bytes > 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes > 1e6) return `${Math.round(bytes / 1e6)} MB`;
  return `${Math.max(1, Math.round(bytes / 1e3))} KB`;
}

function short(text, length = 220) {
  const value = String(text || '').replace(/\s+/g, ' ').trim();
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function destinationOf(item) {
  if (item.kind === 'fetch') {
    try {
      return new URL(item.target).hostname;
    } catch {
      return item.target;
    }
  }
  if (item.kind === 'search') return 'Web search';
  if (item.kind === 'mcp') return `MCP ${item.target.split('__')[1] || item.target}`;
  const words = item.target.trim().split(/\s+/);
  return /^(git|npm|pnpm|yarn|gh|aws|gcloud|az|docker|netlify|vercel)$/.test(words[0]) ? words.slice(0, 2).join(' ') : words[0];
}

function verdict(ledger) {
  const followed = ledger.findings.filter((finding) => finding.kind === 'action-after-injection').length;
  const after = ledger.findings.filter((finding) => finding.kind === 'action-after-untrusted').length;
  if (followed) return `${followed === 1 ? 'Once' : `${followed} times`}, an agent did what a web page or tool result told it to.`;
  if (after) return `${after === 1 ? 'Once' : `${after} times`}, an agent took a consequential action right after reading untrusted instructions.`;
  return 'No agent acted on instructions from untrusted content.';
}

function FindingGroup({ kind, label, findings }) {
  const items = findings.filter((finding) => finding.kind === kind);
  if (items.length === 0) return null;
  return (
    <details open={['action-after-injection', 'action-after-untrusted', 'secret-in-context'].includes(kind)} style={{ borderTop: '1px solid var(--rule)' }}>
      <summary style={{ padding: '12px 22px', cursor: 'pointer', display: 'flex', gap: 12, alignItems: 'baseline', flexWrap: 'wrap' }}>
        <strong>{label}</strong>
        <span className={`sl-sev sl-sevtext-${items[0].severity}`}>{items.length}</span>
      </summary>
      <ul className="sl-findings">
        {items.slice(0, 50).map((finding) => (
          <li key={finding.id} className="sl-finding">
            <div className="sl-finding-static">
              <span className={`sl-finding-bar sl-sevtext-${finding.severity}`} aria-hidden="true" />
              <span>
                <span className="sl-finding-title">
                  <span className={`sl-sevtext-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}.</span> {finding.title}
                </span>
                {finding.action && (
                  <span className="sl-finding-excerpt sl-mono" style={{ display: 'block', fontSize: 13 }}>
                    {short(finding.action)}
                  </span>
                )}
                {finding.excerpt && kind !== 'action-after-untrusted' && (
                  <span className="sl-finding-detail" style={{ display: 'block' }}>
                    {short(finding.excerpt, 260)}
                  </span>
                )}
                <span className="sl-finding-detail" style={{ display: 'block' }}>
                  {finding.source ? `After reading ${short(finding.source, 80)}. ` : ''}
                  {HARNESS_NAME[finding.harness] || finding.harness}
                  {finding.cwd ? ` in ${finding.cwd.split('/').filter(Boolean).pop()}` : ''}, {formatDate(finding.t)}
                </span>
              </span>
            </div>
          </li>
        ))}
      </ul>
      {items.length > 50 && (
        <p className="sl-small" style={{ margin: 0, padding: '0 22px 14px' }}>
          Showing 50 of {items.length}.
        </p>
      )}
    </details>
  );
}

function Results({ ledger, meta }) {
  const [harness, setHarness] = useState('all');
  const destinations = useMemo(() => {
    const counts = new Map();
    for (const item of ledger.egress) counts.set(destinationOf(item), (counts.get(destinationOf(item)) || 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
  }, [ledger]);
  const sessions = ledger.sessions.filter((session) => harness === 'all' || session.harness === harness);
  const { summary } = ledger;

  return (
    <div className="sl-results">
      <div className="sl-stack" style={{ gap: 20 }}>
        <section className="sl-panel" aria-labelledby="rv-findings">
          <div className="sl-page-meta">
            <h2 id="rv-findings" className="sl-page-title">
              What your agents did that deserves a look
            </h2>
            <span className="sl-page-url">
              {summary.sessions} sessions, {formatDate(summary.from)} to {formatDate(summary.to)}
            </span>
          </div>
          {ledger.findings.length === 0 && (
            <p className="sl-support" style={{ margin: 0, padding: '16px 22px' }}>
              Nothing stood out in these sessions.
            </p>
          )}
          {KIND_GROUPS.map(([kind, label]) => (
            <FindingGroup key={kind} kind={kind} label={label} findings={ledger.findings} />
          ))}
        </section>

        <section className="sl-panel" aria-labelledby="rv-sessions">
          <div className="sl-page-meta" style={{ justifyContent: 'space-between' }}>
            <h2 id="rv-sessions" className="sl-page-title">
              Sessions
            </h2>
            <div className="sl-tabs" role="tablist" aria-label="Agent" style={{ margin: 0 }}>
              {['all', ...Object.keys(summary.harnesses)].map((key) => (
                <button key={key} type="button" role="tab" className="sl-tab" aria-selected={harness === key} onClick={() => setHarness(key)}>
                  {key === 'all' ? 'All' : HARNESS_NAME[key] || key}
                </button>
              ))}
            </div>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="sl-prose" style={{ maxWidth: 'none', margin: 0, fontSize: 15 }}>
              <thead>
                <tr>
                  <th style={{ paddingLeft: 22 }}>Started</th>
                  <th>Agent</th>
                  <th>Project</th>
                  <th>Commands</th>
                  <th>Web reads</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {sessions.slice(0, 200).map((session) => (
                  <tr key={`${session.harness}-${session.sessionId}-${session.file}`}>
                    <td style={{ paddingLeft: 22, whiteSpace: 'nowrap' }}>{formatDate(session.startedAt)}</td>
                    <td>{HARNESS_NAME[session.harness] || session.harness}</td>
                    <td style={{ overflowWrap: 'anywhere' }}>{session.project || 'Unknown'}</td>
                    <td>{session.counts.commands}</td>
                    <td>{session.counts.fetches}</td>
                    <td>{session.findings ? <span className={`sl-sev sl-sevtext-${session.worst}`}>{session.findings}</span> : '0'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <aside className="sl-verdict" aria-label="Summary">
        <section className="sl-panel sl-panel-pad">
          <h2 className="sl-verdict-line">{verdict(ledger)}</h2>
          <ul className="sl-legend">
            <li>
              Sessions<span className="sl-legend-value">{summary.sessions}</span>
            </li>
            <li>
              Commands run<span className="sl-legend-value">{summary.commands}</span>
            </li>
            <li>
              Web pages and searches<span className="sl-legend-value">{summary.fetches}</span>
            </li>
            <li>
              MCP tool calls<span className="sl-legend-value">{summary.mcp}</span>
            </li>
            <li>
              Files written<span className="sl-legend-value">{summary.writes}</span>
            </li>
          </ul>
        </section>
        <section className="sl-panel sl-panel-pad">
          <h2 className="sl-h3">What left your machine</h2>
          {destinations.length === 0 ? (
            <p className="sl-support" style={{ margin: 0 }}>
              No network activity was recorded.
            </p>
          ) : (
            <ul className="sl-legend">
              {destinations.map(([name, count]) => (
                <li key={name}>
                  <span style={{ overflowWrap: 'anywhere' }}>{name}</span>
                  <span className="sl-legend-value">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        {ledger.mcpServers.length > 0 && (
          <section className="sl-panel sl-panel-pad">
            <h2 className="sl-h3">MCP servers your agents used</h2>
            <ul className="sl-legend">
              {ledger.mcpServers.slice(0, 12).map((server) => (
                <li key={server.server}>
                  <span style={{ overflowWrap: 'anywhere' }}>{server.server}</span>
                  <span className="sl-legend-value">{server.calls}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        <section className="sl-panel sl-panel-pad">
          <h2 className="sl-h3">What Rearview read</h2>
          <ul className="sl-notes">
            <li>
              {meta.total} file{meta.total === 1 ? '' : 's'}
              {meta.bytes ? `, ${formatBytes(meta.bytes)}` : ''}, read in this tab. Nothing was uploaded.
            </li>
            {meta.skipped > 0 && <li>{meta.skipped} file(s) were not agent sessions or were too large.</li>}
            {meta.capped && <li>Only the {MAX_FILES} most recent files were read.</li>}
            <li>Secrets are shown only as their first four characters.</li>
          </ul>
        </section>
      </aside>
    </div>
  );
}

export default function RearviewPage() {
  const [state, setState] = useState({ status: 'idle' });
  const folderInput = useRef(null);
  const fileInput = useRef(null);

  const run = useCallback((files, samples = []) => {
    const sessionFiles = [...files].filter((file) => file.name.endsWith('.jsonl')).sort((a, b) => b.lastModified - a.lastModified);
    const capped = sessionFiles.length > MAX_FILES;
    const chosen = sessionFiles.slice(0, MAX_FILES);
    if (chosen.length === 0 && samples.length === 0) {
      setState({ status: 'error', message: 'No session logs were found there. Choose ~/.claude/projects or ~/.codex/sessions.' });
      return;
    }
    setState({ status: 'reading', done: 0, total: chosen.length + samples.length, bytes: 0 });
    const worker = new Worker(new URL('../lib/rearview/worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = (event) => {
      if (event.data.type === 'progress') setState((previous) => ({ ...previous, ...event.data }));
      if (event.data.type === 'done') {
        setState({ status: 'ready', ledger: event.data.ledger, meta: { total: event.data.total, bytes: event.data.bytes, skipped: event.data.skipped, capped } });
        worker.terminate();
      }
    };
    worker.onerror = () => {
      setState({ status: 'error', message: 'The session logs could not be read.' });
      worker.terminate();
    };
    worker.postMessage({ files: chosen, samples });
  }, []);

  return (
    <div className="sl-wrap" style={{ paddingBottom: 64 }}>
      <section className="sl-hero" aria-labelledby="rv-head">
        <h1 id="rv-head" className="sl-display" style={{ maxWidth: '17ch' }}>
          What did your agents do?
        </h1>
        <p className="sl-lede">
          Open your agent session logs. Rearview reads Claude Code and Codex sessions in this tab and shows what they ran, what left your
          machine, which secrets they touched, and what they did right after reading untrusted instructions. Nothing is uploaded.
        </p>
        <div className="sl-lens-form" style={{ flexWrap: 'wrap' }}>
          <button type="button" className="sl-button" onClick={() => folderInput.current?.click()} disabled={state.status === 'reading'}>
            Choose a folder
          </button>
          <button type="button" className="sl-button sl-button-quiet" onClick={() => fileInput.current?.click()} disabled={state.status === 'reading'}>
            Choose session files
          </button>
          <button type="button" className="sl-button sl-button-quiet" onClick={() => run([], SAMPLE_FILES)} disabled={state.status === 'reading'}>
            Try sample sessions
          </button>
        </div>
        <input ref={folderInput} type="file" webkitdirectory="" directory="" multiple hidden onChange={(event) => run(event.target.files || [])} />
        <input ref={fileInput} type="file" accept=".jsonl" multiple hidden onChange={(event) => run(event.target.files || [])} />
        <p className="sl-small" style={{ margin: '14px 0 0', maxWidth: '70ch' }}>
          Claude Code keeps sessions in <span className="sl-inline-code">~/.claude/projects</span> and Codex in{' '}
          <span className="sl-inline-code">~/.codex/sessions</span>. On a Mac, press Command-Shift-Period in the folder picker to show hidden
          folders. Chrome may call choosing a folder an upload. The files stay in this tab.
        </p>
        <p className="sl-visually-hidden" aria-live="polite">
          {state.status === 'reading' ? `Reading ${state.done} of ${state.total} files` : state.status === 'ready' ? 'Analysis ready.' : ''}
        </p>
        {state.status === 'reading' && (
          <p className="sl-message" style={{ marginTop: 16, maxWidth: 760 }}>
            Reading {state.done} of {state.total} session files{state.bytes ? `, ${formatBytes(state.bytes)} so far` : ''}.
          </p>
        )}
        {state.status === 'error' && (
          <div className="sl-alert" role="alert">
            {state.message}
          </div>
        )}
      </section>
      {state.status === 'ready' && <Results ledger={state.ledger} meta={state.meta} />}
    </div>
  );
}
