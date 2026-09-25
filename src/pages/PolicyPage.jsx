import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLens } from '../context/LensContext.jsx';
import LensInput from '../components/lens/LensInput.jsx';
import { CodeBlock } from '../components/common/CopyButton.jsx';
import { analyzeUrl, analyzeHtmlLocally } from '../lib/isp/client.js';
import { findDemo } from '../lib/isp/demos.js';
import { generatePolicy, candidateRegions } from '../lib/isp/generate.js';
import { parsePolicy, serializePolicy, isSpoofableSelector } from '../lib/isp/policy.js';
import { INSTRUCTION_KINDS } from '../components/lens/model.js';
import ReportEndpoint from '../components/lens/ReportEndpoint.jsx';

const DELIVERY = [
  { id: 'header', label: 'HTTP header', note: 'Send this response header on every page.' },
  { id: 'netlify', label: 'Netlify or Cloudflare _headers', note: 'Add to the _headers file at your publish root.' },
  { id: 'nginx', label: 'nginx', note: 'Add inside the server or location block.' },
  { id: 'apache', label: 'Apache', note: 'Requires mod_headers.' },
  { id: 'express', label: 'Express', note: 'Set it in middleware before responses are sent.' },
  { id: 'meta', label: 'Meta tag', note: 'Place it inside head, before any user content. Use this only when you cannot set headers.' },
  { id: 'wellKnown', label: 'Well-known file', note: 'Serve as text/plain at /.well-known/instruction-security-policy. It applies site-wide when a page has no header or meta tag.' }
];

function snippetFor(generated, id) {
  if (id === 'header') return generated.header;
  if (id === 'meta') return generated.meta;
  if (id === 'wellKnown') return generated.wellKnown.trim();
  return generated.snippets[id];
}

function Messages({ errors, warnings, failedClosed }) {
  if (!errors.length && !warnings.length) {
    return <p className="sl-message sl-message-ok">The policy parses cleanly.</p>;
  }
  return (
    <div className="sl-stack" style={{ gap: 8 }}>
      {failedClosed && <p className="sl-message sl-message-error" style={{ margin: 0 }}>Agents will ignore every voice grant until the errors are fixed.</p>}
      {errors.map((item, index) => (
        <p key={`e${index}`} className="sl-message sl-message-error" style={{ margin: 0 }}>
          <strong>Error.</strong> {item.message}
        </p>
      ))}
      {warnings.map((item, index) => (
        <p key={`w${index}`} className="sl-message sl-message-warning" style={{ margin: 0 }}>
          <strong>Warning.</strong> {item.message}
        </p>
      ))}
    </div>
  );
}

function TestResult({ before, after, onOpen }) {
  const undeclared = after.findings.filter((finding) => finding.kind === 'undeclared-user-content').length;
  const instructive = after.findings.filter((finding) => INSTRUCTION_KINDS.has(finding.kind) && ['critical', 'high', 'medium'].includes(finding.severity));
  const contained = instructive.filter((finding) => finding.contained).length;
  const uncontained = instructive.length - contained;
  const regionsBefore = before.regions.filter((region) => region.zone === 'untrusted' && region.basis === 'inferred').length;
  return (
    <div className="sl-message sl-message-ok">
      <p style={{ margin: '0 0 8px' }}>
        <strong>With this policy:</strong>{' '}
        {undeclared === 0
          ? regionsBefore === 1
            ? 'the region of user content is declared untrusted.'
            : `all ${regionsBefore} regions of user content are declared untrusted.`
          : `${undeclared} region${undeclared === 1 ? ' still looks' : 's still look'} like user content but ${undeclared === 1 ? 'is' : 'are'} not declared.`}{' '}
        {instructive.length === 1 && contained === 1 && 'The passage that gives agents orders is now marked as someone else speaking.'}
        {instructive.length > 1 && `${contained} of ${instructive.length} passages that give agents orders are now marked as someone else speaking.`}
        {uncontained > 0 && ` ${uncontained} ${uncontained === 1 ? 'is' : 'are'} hidden text or tools, which a policy cannot vouch for, so remove ${uncontained === 1 ? 'it' : 'them'}.`}
      </p>
      <button type="button" className="sl-button sl-button-quiet sl-button-small" onClick={onOpen}>
        Open the page with this policy
      </button>
    </div>
  );
}

function Generator({ report, input, setResult }) {
  const candidates = useMemo(() => candidateRegions(report), [report]);
  const hasTools = (report.tools?.declarative?.length || 0) + (report.tools?.imperative?.length || 0) > 0;
  const existing = report.policy?.present ? report.policy.directives : null;
  const [include, setInclude] = useState(() => new Set(candidates.map((region) => region.id)));
  const [defaultZone, setDefaultZone] = useState(existing?.default || 'voice');
  const [voiceText, setVoiceText] = useState((existing?.voice || []).join(', '));
  const [toolsSelf, setToolsSelf] = useState(hasTools || Boolean(existing?.tools));
  const [instructions, setInstructions] = useState(existing?.instructions || '');
  const [reportTo, setReportTo] = useState(existing?.reportTo || '');
  const [tab, setTab] = useState('header');
  const [test, setTest] = useState(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState(null);

  useEffect(() => {
    setInclude(new Set(candidates.map((region) => region.id)));
    setTest(null);
  }, [candidates]);

  const voiceSelectors = voiceText.split(',').map((item) => item.trim()).filter(Boolean);
  const generated = useMemo(
    () =>
      generatePolicy(report, {
        include: [...include],
        defaultZone,
        voice: voiceSelectors,
        tools: toolsSelf ? ["'self'"] : existing?.tools ?? null,
        instructions: instructions.trim() || null,
        reportTo: reportTo.trim() || null
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [report, include, defaultZone, voiceText, toolsSelf, instructions, reportTo]
  );

  function toggle(id) {
    const next = new Set(include);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setInclude(next);
    setTest(null);
  }

  async function runTest() {
    setTesting(true);
    setTestError(null);
    try {
      let after;
      if (input?.kind === 'url') after = await analyzeUrl(input.url, { policy: generated.policy });
      else if (input?.html) after = await analyzeHtmlLocally(input.html, { url: input.url, headers: { 'instruction-security-policy': generated.policy }, source: input.demoId ? 'demo' : 'pasted-html' });
      else if (input?.demoId) after = await analyzeHtmlLocally(findDemo(input.demoId).html, { url: input.url, headers: { 'instruction-security-policy': generated.policy }, source: 'demo' });
      else throw new Error('Read the page again to test a policy against it.');
      setTest(after);
    } catch (caught) {
      setTestError(caught.message);
    } finally {
      setTesting(false);
    }
  }

  const navigate = useNavigate();
  function openTested() {
    setResult(test, { ...input, label: `${input?.label || input?.url || 'Page'} with a draft policy` });
    navigate('/');
  }

  return (
    <div className="sl-split">
      <div className="sl-stack" style={{ gap: 24 }}>
        <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="sl-h3">User content to mark untrusted</legend>
          {candidates.length === 0 ? (
            <p className="sl-support" style={{ margin: 0 }}>
              The lens found no comments, reviews, or other user content on this page. You can still publish a policy so agents know the
              whole page is yours.
            </p>
          ) : (
            <ul className="sl-region-list">
              {candidates.map((region) => (
                <li key={region.id} className="sl-region">
                  <label className="sl-check">
                    <input type="checkbox" checked={include.has(region.id)} onChange={() => toggle(region.id)} />
                    <span>
                      <strong>{region.label}</strong> <span className="sl-inline-code">{region.suggestedSelector}</span>
                      <span className="sl-small" style={{ display: 'block', marginTop: 4 }}>
                        {region.excerpt || region.reason}
                      </span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
        </fieldset>

        <fieldset style={{ border: 0, padding: 0, margin: 0 }} className="sl-stack">
          <legend className="sl-h3">Everything else on the page</legend>
          <label className="sl-check">
            <input type="radio" name="default-zone" checked={defaultZone === 'voice'} onChange={() => setDefaultZone('voice')} />
            <span>
              <strong>Is the site speaking.</strong>
              <span className="sl-small" style={{ display: 'block' }}>Best when user content lives in a few known places.</span>
            </span>
          </label>
          <label className="sl-check">
            <input type="radio" name="default-zone" checked={defaultZone === 'untrusted'} onChange={() => setDefaultZone('untrusted')} />
            <span>
              <strong>Is untrusted unless I name it.</strong>
              <span className="sl-small" style={{ display: 'block' }}>Best for forums and platforms where most text comes from users.</span>
            </span>
          </label>
          {defaultZone === 'untrusted' && (
            <div>
              <label htmlFor="voice-selectors" className="sl-field-label">
                Regions where the site speaks
              </label>
              <input id="voice-selectors" className="sl-input sl-mono" style={{ fontSize: 15 }} value={voiceText} onChange={(event) => setVoiceText(event.target.value)} placeholder="#site-header, #main-nav, body > footer" />
              {voiceSelectors.some((selector) => isSpoofableSelector(selector)) && (
                <p className="sl-small" style={{ margin: '6px 0 0' }}>
                  Class and attribute selectors can be copied by user content. Use ids or structural selectors for voice.
                </p>
              )}
            </div>
          )}
        </fieldset>

        <fieldset style={{ border: 0, padding: 0, margin: 0 }} className="sl-stack">
          <legend className="sl-h3">Tools and contact</legend>
          <label className="sl-check">
            <input type="checkbox" checked={toolsSelf} onChange={(event) => setToolsSelf(event.target.checked)} />
            <span>
              <strong>Only this site may register agent tools.</strong>
              <span className="sl-small" style={{ display: 'block' }}>{hasTools ? 'This page exposes WebMCP tools.' : 'Adds tools ’self’.'}</span>
            </span>
          </label>
          <div>
            <label htmlFor="instructions-url" className="sl-field-label">
              Where you give agents instructions (optional)
            </label>
            <input id="instructions-url" className="sl-input" value={instructions} onChange={(event) => setInstructions(event.target.value)} placeholder="For example, /llms.txt" />
          </div>
          <div>
            <label htmlFor="report-to" className="sl-field-label">
              Where agents send reports (optional)
            </label>
            <input id="report-to" className="sl-input" value={reportTo} onChange={(event) => setReportTo(event.target.value)} placeholder="For example, https://securitylens.io/r/…" />
            <ReportEndpoint onCreated={(endpoint) => setReportTo(endpoint)} />
          </div>
        </fieldset>
      </div>

      <div className="sl-stack" style={{ alignContent: 'start', gap: 18 }}>
        <div>
          <h2 className="sl-h3">Your policy</h2>
          <CodeBlock code={generated.policy} />
        </div>
        <Messages errors={generated.check.errors} warnings={generated.check.warnings} failedClosed={generated.check.failedClosed} />
        <div>
          <h2 className="sl-h3">Send it</h2>
          <div className="sl-tabs" role="tablist" aria-label="Delivery method">
            {DELIVERY.map((item) => (
              <button key={item.id} type="button" role="tab" className="sl-tab" aria-selected={tab === item.id} onClick={() => setTab(item.id)}>
                {item.label}
              </button>
            ))}
          </div>
          <p className="sl-small" style={{ margin: '0 0 10px' }}>
            {DELIVERY.find((item) => item.id === tab).note}
          </p>
          <CodeBlock code={snippetFor(generated, tab)} />
        </div>
        <div className="sl-stack" style={{ gap: 10 }}>
          <button type="button" className="sl-button" onClick={runTest} disabled={testing}>
            {testing ? 'Testing…' : 'Test this policy on the page'}
          </button>
          {testError && <p className="sl-message sl-message-error" style={{ margin: 0 }}>{testError}</p>}
          {test && <TestResult before={report} after={test} onOpen={openTested} />}
        </div>
      </div>
    </div>
  );
}

const DIRECTIVE_TEXT = {
  default: (value) => (value === 'untrusted' ? 'Text no other directive matches is untrusted.' : 'Text no other directive matches is the site speaking.'),
  voice: (value) => `The site speaks in ${value.length} region${value.length === 1 ? '' : 's'}.`,
  untrusted: (value) => `${value.length} region${value.length === 1 ? ' is' : 's are'} someone else speaking.`,
  tools: (value) => (value.includes("'none'") ? 'No script may register agent tools.' : `Agent tools may come from ${value.map((source) => (source === "'self'" ? 'this site' : source)).join(', ')}.`),
  instructions: (value) => `Agents should look for the site's instructions at ${value}.`,
  reportTo: (value) => `Agents may report violations to ${value}.`
};

function Checker() {
  const [text, setText] = useState("default voice; untrusted #comments, .review-body; tools 'self'");
  const parsed = useMemo(() => parsePolicy(text), [text]);
  const rows = Object.entries(parsed.directives).filter(([key, value]) => value !== null && !(Array.isArray(value) && value.length === 0));

  return (
    <div className="sl-split">
      <div>
        <label htmlFor="policy-check" className="sl-field-label">
          Policy to check
        </label>
        <textarea id="policy-check" className="sl-textarea" rows={6} spellCheck="false" value={text} onChange={(event) => setText(event.target.value)} />
        <p className="sl-small" style={{ margin: '8px 0 0' }}>
          Paste the header value without the header name.
        </p>
      </div>
      <div className="sl-stack" style={{ alignContent: 'start' }}>
        <Messages errors={parsed.errors} warnings={parsed.warnings} failedClosed={parsed.failedClosed} />
        <ul className="sl-notes" style={{ color: 'var(--ink)', fontSize: 15 }}>
          {rows.map(([key, value]) => (
            <li key={key}>{DIRECTIVE_TEXT[key](value)}</li>
          ))}
        </ul>
        <div>
          <h3 className="sl-h3">Normalized</h3>
          <CodeBlock code={serializePolicy(parsed.directives)} />
        </div>
      </div>
    </div>
  );
}

export default function PolicyPage() {
  const lens = useLens();
  const { input, setResult } = lens;
  const report = lens.report?.kind === 'repository' ? null : lens.report;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function run(fn, nextInput) {
    setBusy(true);
    setError(null);
    try {
      setResult(await fn(), nextInput);
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="sl-wrap">
      <section className="sl-hero" style={{ paddingBottom: 24 }} aria-labelledby="policy-head">
        <h1 id="policy-head" className="sl-display" style={{ maxWidth: '18ch' }}>
          Tell agents who is speaking
        </h1>
        <p className="sl-lede">
          Start from a page you have read with the lens. Pick the regions where other people speak, and SecurityLens writes the policy
          and shows you how to send it.
        </p>
      </section>

      <section className="sl-section" aria-labelledby="generator-head">
        <div className="sl-example-caption">
          <h2 id="generator-head" className="sl-h2" style={{ margin: 0 }}>
            {report ? `Policy for ${report.title || report.url || 'this page'}` : 'Start from a page'}
          </h2>
          {report && <span className="sl-small">{report.fetch?.finalUrl || report.url || input?.label}</span>}
        </div>
        {report ? (
          <Generator report={report} input={input} setResult={setResult} />
        ) : (
          <>
            <p className="sl-support" style={{ margin: 0 }}>
              Read a page first. The policy is built from what the lens finds on it.
            </p>
            <LensInput
              busy={busy}
              onUrl={(url) => run(() => analyzeUrl(url), { kind: 'url', url })}
              onHtml={(html) => run(() => analyzeHtmlLocally(html), { kind: 'html', html, label: 'Pasted HTML' })}
              onDemo={(id) => {
                const demo = findDemo(id);
                run(() => analyzeHtmlLocally(demo.html, { url: demo.url, source: 'demo' }), { kind: 'html', html: demo.html, url: demo.url, label: `Example: ${demo.label}`, demoId: id });
              }}
            />
            {error && (
              <div className="sl-alert" role="alert">
                {error}
              </div>
            )}
          </>
        )}
      </section>

      <section className="sl-section" aria-labelledby="checker-head" style={{ paddingBottom: 64 }}>
        <h2 id="checker-head" className="sl-h2">
          Check a policy
        </h2>
        <Checker />
      </section>
    </div>
  );
}
