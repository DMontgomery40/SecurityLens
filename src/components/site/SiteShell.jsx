import React from 'react';
import { NavLink, Link } from 'react-router-dom';

const NAV = [
  { to: '/', label: 'Lens', end: true },
  { to: '/policy', label: 'Policy' },
  { to: '/spec', label: 'Spec' },
  { to: '/agents', label: 'For agents' },
  { to: '/rearview', label: 'Rearview' },
  { to: '/scanner', label: 'Code scanner' }
];

function Wordmark() {
  return (
    <Link to="/" className="sl-wordmark" aria-label="SecurityLens home">
      <span className="sl-wordmark-mark" aria-hidden="true">
        <span style={{ background: 'var(--voice)' }} />
        <span style={{ background: 'var(--untrusted-bar)' }} />
        <span style={{ background: 'var(--hidden)' }} />
      </span>
      SecurityLens
    </Link>
  );
}

export default function SiteShell({ children }) {
  return (
    <div className="sl-app">
      <a href="#main" className="sl-visually-hidden">
        Skip to content
      </a>
      <header className="sl-header">
        <div className="sl-wrap sl-header-inner">
          <Wordmark />
          <nav className="sl-nav" aria-label="Main">
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end}>
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main id="main">{children}</main>
      <footer className="sl-footer">
        <div className="sl-wrap sl-footer-inner">
          <p style={{ margin: 0 }}>SecurityLens is open source under the MIT license.</p>
          <nav aria-label="Footer">
            <Link to="/spec">Instruction Security Policy</Link>
            <Link to="/agents">MCP and API</Link>
            <a href="https://github.com/DMontgomery40/SecurityLens">Source on GitHub</a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
