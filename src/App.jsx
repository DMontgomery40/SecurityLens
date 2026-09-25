import React, { useEffect } from 'react';
import Decoder from './components/Decoder';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import AppErrorBoundary from './components/AppErrorBoundary';
import Home from './components/Home';
import { createLogger, createRequestId } from './lib/logger.js';

const logger = createLogger({
  component: 'App'
});

function App() {
  useEffect(() => {
    // Ensure dark mode is always active
    document.documentElement.classList.add('dark');

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
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/secret" element={<Decoder />} />
        </Routes>
      </Router>
    </AppErrorBoundary>
  );
}

export default App;
