import React, { useState } from 'react';
import { CodeBlock } from '../common/CopyButton.jsx';

export default function ReportEndpoint({ onCreated }) {
  const [state, setState] = useState({ status: 'idle' });

  async function create() {
    setState({ status: 'busy' });
    try {
      const response = await fetch('/api/reports', { method: 'POST' });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message || `HTTP ${response.status}`);
      setState({ status: 'done', ...body });
      onCreated(body.endpoint);
    } catch (error) {
      setState({ status: 'error', message: error.message });
    }
  }

  if (state.status === 'done') {
    return (
      <div className="sl-message sl-message-warning" style={{ marginTop: 10 }}>
        <p style={{ margin: '0 0 8px' }}>
          <strong>Save this link now.</strong> It is the only way to read the reports agents send to your new endpoint.
        </p>
        <CodeBlock code={state.viewUrl} copyLabel="Copy link" />
      </div>
    );
  }

  return (
    <p className="sl-small" style={{ margin: '8px 0 0' }}>
      No endpoint yet?{' '}
      <button type="button" className="sl-linkbutton" onClick={create} disabled={state.status === 'busy'}>
        {state.status === 'busy' ? 'Creating…' : 'Create a free SecurityLens endpoint'}
      </button>
      {state.status === 'error' && <span role="alert"> Could not create one: {state.message}</span>}
    </p>
  );
}
