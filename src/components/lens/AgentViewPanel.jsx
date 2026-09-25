import React, { useState } from 'react';
import { loadAgentView } from '../../lib/isp/client.js';
import { CodeBlock } from '../common/CopyButton.jsx';

export default function AgentViewPanel({ report }) {
  const [view, setView] = useState(null);
  const [open, setOpen] = useState(false);

  async function toggle() {
    if (!open && !view) setView(await loadAgentView(report));
    setOpen(!open);
  }

  return (
    <section className="sl-panel sl-panel-pad" aria-labelledby="agent-view-head" style={{ marginTop: 20 }}>
      <div className="sl-example-caption" style={{ marginBottom: open ? 12 : 0 }}>
        <div>
          <h2 id="agent-view-head" className="sl-h3" style={{ margin: 0 }}>
            What an agent receives
          </h2>
          <p className="sl-small" style={{ margin: '4px 0 0' }}>
            The same page through the SecurityLens MCP tool, with speakers marked and hidden text removed.
          </p>
        </div>
        <button type="button" className="sl-button sl-button-quiet sl-button-small" onClick={toggle} aria-expanded={open}>
          {open ? 'Hide' : 'Show agent view'}
        </button>
      </div>
      {open && view && <CodeBlock code={view.text} copyLabel="Copy" />}
    </section>
  );
}
