import React from 'react';
import { createLogger, createRequestId } from '../lib/logger.js';

const logger = createLogger({
  component: 'AppErrorBoundary'
});

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      requestId: null
    };
  }

  static getDerivedStateFromError() {
    return {
      hasError: true,
      requestId: createRequestId('ui')
    };
  }

  componentDidCatch(error, info) {
    logger.error(
      {
        err: error,
        requestId: this.state.requestId,
        componentStack: info.componentStack
      },
      'Unhandled React render error'
    );
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center px-6">
          <div className="max-w-lg rounded-xl border border-red-500/40 bg-gray-800/80 p-6 shadow-xl">
            <h1 className="text-2xl font-semibold text-red-300">Something went wrong</h1>
            <p className="mt-3 text-sm text-gray-200">
              The page hit an unexpected error. Refresh the page and try again.
            </p>
            {this.state.requestId && (
              <p className="mt-4 text-xs text-gray-400">
                Reference ID: {this.state.requestId}
              </p>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default AppErrorBoundary;
