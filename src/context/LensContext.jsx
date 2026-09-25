import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';

const STORAGE_KEY = 'securitylens:last-lens';
const LensContext = createContext(null);

function readStored() {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeStored(value) {
  try {
    if (value) window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value));
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage can be unavailable in private windows; the lens still works.
  }
}

// Holds the most recent analysis so the Policy page can build on it.
// `input` records how the report was produced: { kind: 'url', url } or
// { kind: 'html', html, url, label }.
export function LensProvider({ children }) {
  const [state, setState] = useState(() => readStored());

  const setResult = useCallback((report, input) => {
    const next = report ? { report, input } : null;
    setState(next);
    const storable = next && next.input?.kind === 'html' && next.input.html.length > 400000 ? { report, input: { ...input, html: null } } : next;
    writeStored(storable);
  }, []);

  const value = useMemo(() => ({ report: state?.report || null, input: state?.input || null, setResult }), [state, setResult]);
  return <LensContext.Provider value={value}>{children}</LensContext.Provider>;
}

export function useLens() {
  const context = useContext(LensContext);
  if (!context) throw new Error('useLens must be used inside LensProvider');
  return context;
}
