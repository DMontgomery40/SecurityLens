import React, { useState } from 'react';
import { DEMOS } from '../../lib/isp/demos.js';

export default function LensInput({ busy, onUrl, onHtml, onDemo, initialUrl = '', showDemos = true }) {
  const [mode, setMode] = useState('url');
  const [url, setUrl] = useState(initialUrl);
  const [html, setHtml] = useState('');

  function submit(event) {
    event.preventDefault();
    if (mode === 'url') {
      const value = url.trim();
      if (!value) return;
      onUrl(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    } else if (html.trim()) {
      onHtml(html);
    }
  }

  return (
    <form onSubmit={submit} aria-label="Read a page">
      {mode === 'url' ? (
        <div className="sl-lens-form">
          <label htmlFor="lens-url" className="sl-visually-hidden">
            Page address
          </label>
          <input
            id="lens-url"
            className="sl-input"
            type="text"
            inputMode="url"
            autoComplete="url"
            spellCheck="false"
            placeholder="A page URL, or a GitHub repository"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
          />
          <button type="submit" className="sl-button" disabled={busy}>
            {busy ? 'Reading the page…' : 'Read the page'}
          </button>
        </div>
      ) : (
        <div style={{ marginTop: 28, maxWidth: 760 }}>
          <label htmlFor="lens-html" className="sl-field-label">
            Page HTML
          </label>
          <textarea
            id="lens-html"
            className="sl-textarea"
            rows={9}
            spellCheck="false"
            placeholder="Paste the page source, or the rendered HTML from your browser's developer tools."
            value={html}
            onChange={(event) => setHtml(event.target.value)}
          />
          <p className="sl-small" style={{ margin: '8px 0 12px' }}>
            Pasted HTML is analyzed in your browser and never uploaded.
          </p>
          <button type="submit" className="sl-button" disabled={busy}>
            {busy ? 'Reading…' : 'Read this HTML'}
          </button>
        </div>
      )}
      <div className="sl-lens-extra">
        <button type="button" className="sl-linkbutton" onClick={() => setMode(mode === 'url' ? 'html' : 'url')}>
          {mode === 'url' ? 'Paste HTML instead' : 'Enter a URL instead'}
        </button>
        {showDemos && (
          <>
            <span>Try an example:</span>
            {DEMOS.map((demo) => (
              <button key={demo.id} type="button" className="sl-demo-chip" onClick={() => onDemo(demo.id)}>
                {demo.label}
              </button>
            ))}
          </>
        )}
      </div>
    </form>
  );
}
