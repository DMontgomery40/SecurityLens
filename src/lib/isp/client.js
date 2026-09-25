// Browser entry points for the lens. URL analysis runs on the server because
// browsers cannot fetch other sites; pasted HTML never leaves the browser.

export async function analyzeUrl(url, { policy } = {}) {
  const response = await fetch('/api/lens', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(policy ? { url, policy } : { url })
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new Error(body?.error?.message || `The lens could not read that page (HTTP ${response.status}).`);
  }
  return body;
}

export async function analyzeHtmlLocally(html, { url = null, headers = {}, source = 'pasted-html' } = {}) {
  const { analyzeDocument } = await import('./analyze.js');
  return analyzeDocument({ html, url, headers, source });
}

export async function loadAgentView(report) {
  const { toAgentView } = await import('./agentView.js');
  return toAgentView(report);
}

export async function loadGenerator() {
  return import('./generate.js');
}
