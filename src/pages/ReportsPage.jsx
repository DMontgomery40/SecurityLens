import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { CodeBlock } from '../components/common/CopyButton.jsx';

function readKey() {
  const match = window.location.hash.match(/key=([A-Za-z0-9_-]+)/);
  return match ? match[1] : '';
}

export default function ReportsPage() {
  const { id } = useParams();
  const [key] = useState(readKey);
  const [state, setState] = useState({ status: 'loading' });

  useEffect(() => {
    if (!key) {
      setState({ status: 'error', message: 'This link is missing its view key. Use the full link you saved when you created the endpoint.' });
      return;
    }
    fetch(`/api/reports?id=${encodeURIComponent(id)}`, { headers: { authorization: `Bearer ${key}` } })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok) throw new Error(body?.error?.message || `HTTP ${response.status}`);
        setState({ status: 'ready', ...body });
      })
      .catch((error) => setState({ status: 'error', message: error.message }));
  }, [id, key]);

  const endpoint = `${window.location.origin}/r/${id}`;
  const sample = `curl -X POST ${endpoint} \\\n  -H 'content-type: application/json' \\\n  -d '{"type":"isp-violation","documentURL":"https://example.com/post/1","zone":"untrusted","rule":"instruction-override","excerpt":"Test report"}'`;

  return (
    <div className="sl-wrap" style={{ paddingBottom: 64 }}>
      <section className="sl-hero" style={{ paddingBottom: 24 }}>
        <h1 className="sl-display" style={{ maxWidth: '20ch' }}>
          Reports from agents
        </h1>
        <p className="sl-lede">
          Agents that honor your policy send a report here when they find instructions inside content you marked untrusted.
        </p>
      </section>

      {state.status === 'loading' && <p>Loading reports…</p>}
      {state.status === 'error' && (
        <div className="sl-alert" role="alert">
          {state.message}
        </div>
      )}
      {state.status === 'ready' && (
        <div className="sl-stack" style={{ gap: 24 }}>
          <p className="sl-support" style={{ margin: 0 }}>
            {state.total === 0 ? 'No reports yet.' : `${state.total} report${state.total === 1 ? '' : 's'} received.`} Endpoint{' '}
            <span className="sl-inline-code">{endpoint}</span>
          </p>
          {state.reports.length > 0 ? (
            <div className="sl-panel" style={{ overflowX: 'auto' }}>
              <table className="sl-prose" style={{ maxWidth: 'none', margin: 0 }}>
                <thead>
                  <tr>
                    <th style={{ paddingLeft: 22 }}>Received</th>
                    <th>Page</th>
                    <th>Rule</th>
                    <th>Excerpt</th>
                    <th>Agent</th>
                  </tr>
                </thead>
                <tbody>
                  {state.reports.map((report, index) => (
                    <tr key={`${report.receivedAt}-${index}`}>
                      <td style={{ paddingLeft: 22, whiteSpace: 'nowrap' }}>{new Date(report.receivedAt).toLocaleString()}</td>
                      <td style={{ overflowWrap: 'anywhere' }}>{report.documentURL || 'Not given'}</td>
                      <td>{report.rule || 'Not given'}</td>
                      <td style={{ overflowWrap: 'anywhere' }}>{report.excerpt || ''}</td>
                      <td>{report.agent || 'Not given'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="sl-stack">
              <p style={{ margin: 0 }}>Send a test report to check that everything is wired up:</p>
              <CodeBlock code={sample} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
