import React, { useEffect } from 'react';
import Decoder from './components/Decoder';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import AppErrorBoundary from './components/AppErrorBoundary';
import SiteShell from './components/site/SiteShell.jsx';
import { LensProvider } from './context/LensContext.jsx';
import LensPage from './pages/LensPage.jsx';
import PolicyPage from './pages/PolicyPage.jsx';
import SpecPage from './pages/SpecPage.jsx';
import AgentsPage from './pages/AgentsPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import ScannerPage from './pages/ScannerPage.jsx';
import RearviewPage from './pages/RearviewPage.jsx';
import { createLogger, createRequestId } from './lib/logger.js';

const logger = createLogger({
  component: 'App'
});

function App() {
  useEffect(() => {
    const handleWindowError = (event) => {
      logger.error(
        {
          err: event.error || new Error(event.message),
          requestId: createRequestId('ui'),
          source: event.filename,
          line: event.lineno,
          column: event.colno
        },
        'Unhandled browser error'
      );
    };

    const handleUnhandledRejection = (event) => {
      logger.error(
        {
          err: event.reason instanceof Error ? event.reason : new Error(String(event.reason)),
          requestId: createRequestId('ui')
        },
        'Unhandled promise rejection'
      );
    };

    window.addEventListener('error', handleWindowError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      window.removeEventListener('error', handleWindowError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  return (
    <AppErrorBoundary>
      <Router>
        <LensProvider>
          <Routes>
            <Route path="/" element={<SiteShell><LensPage /></SiteShell>} />
            <Route path="/policy" element={<SiteShell><PolicyPage /></SiteShell>} />
            <Route path="/spec" element={<SiteShell><SpecPage /></SiteShell>} />
            <Route path="/agents" element={<SiteShell><AgentsPage /></SiteShell>} />
            <Route path="/reports/:id" element={<SiteShell><ReportsPage /></SiteShell>} />
            <Route path="/rearview" element={<SiteShell><RearviewPage /></SiteShell>} />
            <Route path="/scanner" element={<SiteShell><ScannerPage /></SiteShell>} />
            <Route path="/secret" element={<Decoder />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </LensProvider>
      </Router>
    </AppErrorBoundary>
  );
}

export default App;
