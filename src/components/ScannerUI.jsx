import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle2, Settings, Trash2, RefreshCw } from 'lucide-react';
import VulnerabilityScanner from '../lib/scanner';
import { repoCache } from '../lib/cache';
import ScanButton from './ScanButton';
import ScanResults from './ScanResults';
import { Alert, AlertDescription } from './ui/alert';

const ScannerUI = () => {
  const [scanResults, setScanResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [urlInput, setUrlInput] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [showSettings, setShowSettings] = useState(false);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [usedCache, setUsedCache] = useState(false);

  // Load token from localStorage on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('github_token');
    if (savedToken) {
      setGithubToken(savedToken);
    }
  }, []);

  // Save token to localStorage when it changes
  useEffect(() => {
    if (githubToken) {
      localStorage.setItem('github_token', githubToken);
    } else {
      localStorage.removeItem('github_token');
    }
  }, [githubToken]);

  const handleClearCache = () => {
    repoCache.clear();
    setSuccessMessage('Cache cleared successfully');
    setTimeout(() => setSuccessMessage(''), 3000);
  };

  const handleFileSelect = async (event) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setProgress({ current: 0, total: files.length });
    setUsedCache(false);

    try {
      const scanner = new VulnerabilityScanner();
      let allFindings = [];

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setProgress((prev) => ({ ...prev, current: i + 1 }));

        const content = await file.text();
        const findings = await scanner.scanFile(content, file.name);
        if (findings.length > 0) {
          allFindings = [...allFindings, ...findings];
        }
      }

      if (allFindings.length === 0) {
        setSuccessMessage(
          `${files.length} file${files.length > 1 ? 's' : ''} scanned. No vulnerabilities found!`
        );
      } else {
        const report = scanner.generateReport(allFindings);
        setScanResults(report);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  const handleUrlScan = async () => {
    if (!urlInput) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setUsedCache(false);

    try {
      const scanner = new VulnerabilityScanner();
      const { files, rateLimit, fromCache } = await scanner.fetchRepositoryFiles(urlInput, githubToken);
      setRateLimitInfo(rateLimit);
      setUsedCache(fromCache);
      setProgress({ current: 0, total: files.length });

      let allFindings = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setProgress((prev) => ({ ...prev, current: i + 1 }));
        const findings = await scanner.scanFile(file.content, file.path);
        if (findings.length > 0) {
          allFindings = [...allFindings, ...findings];
        }
      }

      if (allFindings.length === 0) {
        setSuccessMessage(`Repository scanned. No vulnerabilities found! ${fromCache ? '(Used cached data)' : ''}`);
      } else {
        const report = scanner.generateReport(allFindings);
        setScanResults(report);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  return (
    <div className="p-8 bg-gray-100 min-h-screen">
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-extrabold text-gray-800">🔒 Plugin Vulnerability Scanner</h1>
        <p className="text-lg text-gray-600 mt-2">
          Scan JavaScript files or repositories for security vulnerabilities
        </p>
      </div>

      {/* Settings Toggle */}
      <div className="mb-4 flex justify-end">
        <button
          onClick={() => setShowSettings(!showSettings)}
          className="flex items-center text-gray-600 hover:text-gray-900"
        >
          <Settings className="h-5 w-5 mr-2" />
          Settings
        </button>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="mb-6 p-4 bg-white rounded-lg shadow">
          <h3 className="text-lg font-medium mb-2">GitHub Settings</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Personal Access Token
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              </label>
              <p className="text-sm text-gray-500 mt-1">
                Adding a token increases API rate limits and allows scanning private repositories.
                {rateLimitInfo && (
                  <span className="ml-2">
                    Remaining API calls: {rateLimitInfo.remaining}/{rateLimitInfo.limit}
                  </span>
                )}
              </p>
            </div>

            <div className="flex items-center justify-between pt-2 border-t">
              <div>
                <h4 className="text-sm font-medium text-gray-700">Cache Management</h4>
                <p className="text-sm text-gray-500">Clear cached repository data to force fresh scans</p>
              </div>
              <button
                onClick={handleClearCache}
                className="flex items-center px-3 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Clear Cache
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scan Interface */}
      <ScanButton
        urlInput={urlInput}
        setUrlInput={setUrlInput}
        handleUrlScan={handleUrlScan}
        handleFileSelect={handleFileSelect}
        scanning={scanning}
      />

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
            Scanning file {progress.current} of {progress.total}
          </div>
        </div>
      )}

      {/* Rate Limit Warning */}
      {rateLimitInfo && rateLimitInfo.remaining < 10 && (
        <Alert className="mb-4">
          <AlertDescription>
            GitHub API rate limit is running low ({rateLimitInfo.remaining} requests remaining).
            {!githubToken && ' Consider adding a GitHub token to increase the limit.'}
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
          <div>
            <span className="font-semibold">Error:</span> {error}
          </div>
        </div>
      )}

      {/* Scan Results */}
      <ScanResults results={scanResults} usedCache={usedCache} />
    </div>
  );
};

export default ScannerUI;