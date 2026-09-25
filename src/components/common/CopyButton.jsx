import React, { useState } from 'react';

export default function CopyButton({ text, label = 'Copy' }) {
  const [state, setState] = useState('idle');

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState('copied');
    } catch {
      setState('failed');
    }
    setTimeout(() => setState('idle'), 1800);
  }

  return (
    <button type="button" className="sl-button sl-button-quiet sl-button-small" onClick={copy} aria-live="polite">
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
    </button>
  );
}

export function CodeBlock({ code, copyLabel }) {
  return (
    <div className="sl-code-row">
      <pre className="sl-code">
        <code>{code}</code>
      </pre>
      <CopyButton text={code} label={copyLabel} />
    </div>
  );
}
