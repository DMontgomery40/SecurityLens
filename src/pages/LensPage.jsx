import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import LensInput from '../components/lens/LensInput.jsx';
import Transcript from '../components/lens/Transcript.jsx';
import VerdictPanel from '../components/lens/VerdictPanel.jsx';
import AgentViewPanel from '../components/lens/AgentViewPanel.jsx';
import { CodeBlock } from '../components/common/CopyButton.jsx';
import { analyzeUrl, analyzeHtmlLocally } from '../lib/isp/client.js';
import { findDemo } from '../lib/isp/demos.js';
import { useLens } from '../context/LensContext.jsx';

function Results({ report, label }) {
  return (
    <div className="sl-results">
      <div>
        <section className="sl-panel" aria-labelledby="page-title">
          <div className="sl-page-meta">
            <h2 id="page-title" className="sl-page-title">
              {report.title || 'Untitled page'}
            </h2>
            <span className="sl-page-url">{label || report.url || 'Pasted HTML'}</span>
          </div>
          <Transcript report={report} />
        </section>
        <AgentViewPanel report={report} />
      </div>
      <VerdictPanel report={report} />
    </div>
  );
}

function Example({ onOpen }) {
  const [report, setReport] = useState(null);
  useEffect(() => {
    const demo = findDemo('poisoned-comment');
    analyzeHtmlLocally(demo.html, { url: demo.url, source: 'demo' }).then(setReport).catch(() => setReport(null));
  }, []);
  if (!report) return null;
  return (
    <section aria-labelledby="example-head" style={{ paddingBottom: 48 }}>
      <div className="sl-example-caption">
        <h2 id="example-head" className="sl-h2" style={{ margin: 0 }}>
          A blog post, read by speaker
        </h2>
        <button type="button" className="sl-button sl-button-quiet sl-button-small" onClick={() => onOpen('poisoned-comment')}>
          Open the full analysis
        </button>
      </div>
      <div className="sl-panel">
        <Transcript report={report} label="Example transcript" />
      </div>
    </section>
  );
}

function Explainers() {
  return (
    <section className="sl-section">
      <div className="sl-split">
        <div className="sl-stack">
          <h2 className="sl-h2">Declare who is speaking</h2>
          <p className="sl-support" style={{ margin: 0, fontSize: 17 }}>
            An Instruction Security Policy is one response header. It tells agents which parts of your pages are you and which are other
            people, so instructions hidden in a comment never read as yours.
          </p>
          <CodeBlock code={'Instruction-Security-Policy: default voice; untrusted #comments, .review-body'} />
          <p style={{ margin: 0 }}>
            <Link to="/policy">Write a policy</Link> or <Link to="/spec">read the spec</Link>.
          </p>
        </div>
        <div className="sl-stack">
          <h2 className="sl-h2">Give your agent the same view</h2>
          <p className="sl-support" style={{ margin: 0, fontSize: 17 }}>
            Connect SecurityLens over MCP and your agent reads pages with every passage attributed, hidden text removed, and a warning
            when something tries to give it orders.
          </p>
          <CodeBlock code={'claude mcp add --transport http securitylens https://securitylens.io/mcp'} />
          <p style={{ margin: 0 }}>
            <Link to="/agents">Setup for other agents and the HTTP API</Link>.
          </p>
        </div>
      </div>
    </section>
  );
}

export default function LensPage() {
  const { report, input, setResult } = useLens();
  const [params, setParams] = useSearchParams();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState('');
  const resultsRef = useRef(null);
  const handledParam = useRef(null);

  const showResults = useCallback(() => {
    requestAnimationFrame(() => resultsRef.current?.scrollIntoView({ block: 'start', behavior: 'auto' }));
  }, []);

  const runUrl = useCallback(
    async (url) => {
      setBusy(true);
      setError(null);
      setStatus(`Reading ${url}`);
      try {
        const result = await analyzeUrl(url);
        setResult(result, { kind: 'url', url });
        setParams({ url }, { replace: true });
        setStatus('Analysis ready.');
        showResults();
      } catch (caught) {
        setError(caught.message);
        setStatus('');
      } finally {
        setBusy(false);
      }
    },
    [setResult, setParams, showResults]
  );

  const runHtml = useCallback(
    async (html, { url = null, label = 'Pasted HTML', source = 'pasted-html', paramsNext = {}, demoId = null } = {}) => {
      setBusy(true);
      setError(null);
      try {
        const result = await analyzeHtmlLocally(html, { url, source });
        setResult(result, { kind: 'html', html, url, label, demoId });
        setParams(paramsNext, { replace: true });
        setStatus('Analysis ready.');
        showResults();
      } catch (caught) {
        setError(caught.message || 'The HTML could not be analyzed.');
      } finally {
        setBusy(false);
      }
    },
    [setResult, setParams, showResults]
  );

  const runDemo = useCallback(
    (id) => {
      const demo = findDemo(id);
      if (demo) runHtml(demo.html, { url: demo.url, label: `Example: ${demo.label}`, source: 'demo', paramsNext: { demo: id }, demoId: id });
    },
    [runHtml]
  );

  useEffect(() => {
    const url = params.get('url');
    const demo = params.get('demo');
    const key = url ? `url:${url}` : demo ? `demo:${demo}` : null;
    if (!key || handledParam.current === key) return;
    handledParam.current = key;
    if (url && !(input?.kind === 'url' && input.url === url && report)) runUrl(url);
    if (demo && !(input?.demoId === demo && report)) runDemo(demo);
  }, [params, input, report, runUrl, runDemo]);

  const label = input?.kind === 'url' ? report?.fetch?.finalUrl || input.url : input?.label;

  return (
    <>
      <div className="sl-wrap">
        <section className="sl-hero" aria-labelledby="lens-head">
          <h1 id="lens-head" className="sl-display">
            Who is speaking on this page?
          </h1>
          <p className="sl-lede">
            Agents read every word on a page as if the site said it. SecurityLens shows which words are the site's, which belong to other
            people, and which are hidden, then flags anything that tries to give an agent orders.
          </p>
          <LensInput busy={busy} onUrl={runUrl} onHtml={(html) => runHtml(html)} onDemo={runDemo} initialUrl={input?.kind === 'url' ? input.url : ''} />
          <p className="sl-visually-hidden" aria-live="polite">
            {status}
          </p>
          {error && (
            <div className="sl-alert" role="alert">
              <strong>That page could not be read.</strong> {error}
            </div>
          )}
        </section>
        <div ref={resultsRef} style={{ scrollMarginTop: 16 }}>
          {report ? <Results report={report} label={label} /> : <Example onOpen={runDemo} />}
        </div>
      </div>
      <div className="sl-wrap">
        <Explainers />
      </div>
    </>
  );
}
