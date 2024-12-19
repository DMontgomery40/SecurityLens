import React, { useState, useEffect, useCallback } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Settings, 
  Trash2, 
  RefreshCw, 
  Shield 
} from 'lucide-react';
import { validateGitHubToken, scanRepository } from '../lib/apiClient';
import { repoCache } from '../lib/cache';
import VulnerabilityScanner from '../lib/scanner';
import ScanButton from './ScanButton';
import ScanResults from './ScanResults';
import { Alert, AlertDescription } from './ui/alert';

// Constants for localStorage keys
const SECURE_TOKEN_KEY = 'secure_github_token';
const TOKEN_EXPIRY_KEY = 'token_expiry';

const ScannerUI = () => {
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [usedCache, setUsedCache] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [urlInput, setUrlInput] = useState('');
  const [tokenValidated, setTokenValidated] = useState(false);
  const [tokenValidating, setTokenValidating] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  const handleUrlScan = useCallback(async () => {
    if (!urlInput) return;
    
    setScanning(true);
    setError(null);
    setUsedCache(false);
    
    try {
      const results = await scanRepository(urlInput);
      setScanResults(results);
      if (results.rateLimit) {
        setRateLimitInfo(results.rateLimit);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  }, [urlInput]);

  // Component rendering:
  return (
    <div className="p-8 bg-gray-100 min-h-screen">
      {/* Cache Indicator */}
      {usedCache && (
        <div className="mb-4 flex items-center justify-center text-gray-600">
          <RefreshCw className="h-4 w-4 mr-2" />
          <span className="text-sm">Using cached repository data</span>
        </div>
      )}

      {/* Progress Bar */}
      {scanning && progress.total > 0 && (
        <div className="mb-6">
          <div className="w-full bg-gray-300 rounded-full h-3">
            <div
              className="bg-blue-600 h-3 rounded-full transition-all duration-300"
              style={{ width: `${(progress.current / progress.total) * 100}%` }}
            ></div>
          </div>
          <div className="text-sm text-gray-700 mt-2 text-center">
            {progress.current === progress.total ? 
              'Processing results...' : 
              `Scanning file ${progress.current} of ${progress.total}`
            }
          </div>
        </div>
      )}

      {/* Rate Limit Warning */}
      {rateLimitInfo && rateLimitInfo.remaining < 10 && (
        <Alert className="mb-4" variant="warning">
          <AlertDescription>
            GitHub API rate limit is running low ({rateLimitInfo.remaining} requests remaining).
            {!tokenValidated && ' Consider adding a GitHub token to increase the limit.'}
          </AlertDescription>
        </Alert>
      )}

      {/* Token Validation Status */}
      {tokenValidating && (
        <Alert className="mb-4" variant="info">
          <AlertDescription>
            Validating GitHub token...
          </AlertDescription>
        </Alert>
      )}

      {/* Success Message */}
      {successMessage && (
        <div className="mb-6 p-5 bg-green-100 text-green-700 rounded-lg flex items-center">
          <CheckCircle2 className="h-6 w-6 mr-3" />
          <span className="text-lg">{successMessage}</span>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-5 bg-red-100 text-red-700 rounded-lg flex items-start">
          <AlertTriangle className="h-6 w-6 mr-3 mt-1" />
          <div className="flex-1">
            <span className="font-semibold">Error: </span>
            <span>{error}</span>
            {error.includes('token') && !tokenValidated && (
              <div className="mt-2 text-sm">
                Please check your GitHub token in settings or try generating a new one.
              </div>
            )}
            {error.includes('rate limit') && (
              <div className="mt-2 text-sm">
                Please wait a few minutes before trying again.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Scan Results */}
      <ScanResults 
        results={scanResults} 
        usedCache={usedCache}
        onRefreshRequest={handleUrlScan}
        scanning={scanning}
      />

      {/* Token Required Warning */}
      {!tokenValidated && urlInput.includes('/private/') && (
        <Alert className="mt-4" variant="warning">
          <AlertDescription>
            Scanning private repositories requires a valid GitHub token.
            Please add your token in the settings.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};

export default ScannerUI;