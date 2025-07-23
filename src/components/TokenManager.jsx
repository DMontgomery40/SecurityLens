import React from 'react';
import { authManager } from '../lib/githubAuth';

const TokenManager = ({ token, onTokenChange, showDialog, onShowDialog, onTokenSubmit, error }) => {
  const handleTokenSubmit = async (inputToken) => {
    if (!inputToken) return;

    if (!authManager.isValidTokenFormat(inputToken)) {
      if (onTokenSubmit) {
        onTokenSubmit(inputToken, 'Invalid token format. Please ensure you\'ve copied the entire token.');
      }
      return;
    }

    if (onTokenSubmit) {
      onTokenSubmit(inputToken);
    }
  };

  if (!token) {
    return (
      <div className="bg-gray-800 p-6 rounded-lg shadow mt-6">
        <h2 className="text-lg font-semibold text-gray-200 mb-4">GitHub Access Token</h2>
        <p className="text-sm text-gray-400 mb-4">
          To scan repositories, you'll need a GitHub personal access token.
          This stays in your browser and is never sent to any server.
        </p>
        <input
          type="password"
          placeholder="GitHub token"
          onChange={(e) => handleTokenSubmit(e.target.value)}
          className="w-full px-4 py-2 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-700 text-white"
        />
        <a
          href="https://github.com/settings/tokens/new"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-blue-400 hover:underline mt-2 inline-block"
        >
          Generate a token
        </a>
      </div>
    );
  }

  return null;
};

export default TokenManager;