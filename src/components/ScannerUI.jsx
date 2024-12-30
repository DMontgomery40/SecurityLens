import React, { useState, useCallback } from 'react';
import { 
  AlertTriangle, 
  Shield 
} from 'lucide-react';
import { scanRepository } from '../lib/apiClient';
import { Alert, AlertDescription } from './ui/alert';
import VulnerabilityScanner from '../lib/scanner';
import ScanResults from './ScanResults';
import { authManager } from '../lib/githubAuth';
import { AlertDialog, AlertDialogContent, AlertDialogHeader } from './ui/alert-dialog';

const ScannerUI = () => {
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [urlInput, setUrlInput] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [scanResults, setScanResults] = useState(null);
  const [usedCache, setUsedCache] = useState(false);
  const [githubToken, setGithubToken] = useState(authManager.getToken() || '');
  const [showTokenDialog, setShowTokenDialog] = useState(false);

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setScanning(true);
    setError(null);
    setProgress({ current: 0, total: files.length });
    setScanResults(null);
    setUsedCache(false);
    
    try {
      const scanner = new VulnerabilityScanner({
        enableNewPatterns: true,
        enablePackageScanners: true
      });

      let allFindings = [];
      let processedFiles = 0;

      for (const file of files) {
        try {
          const content = await file.text();
          const fileFindings = await scanner.scanFile(content, file.name);
          allFindings.push(...fileFindings);
          processedFiles++;
          setProgress({ current: processedFiles, total: files.length });
        } catch (err) {
          console.error(`Error scanning file ${file.name}:`, err);
        }
      }

      // Process findings to ensure proper structure
      const processedFindings = allFindings.map(finding => ({
        ...finding,
        severity: finding.severity || 'LOW',
        description: finding.description || 'No description provided',
        allLineNumbers: { [finding.file]: finding.lineNumbers || [] }
      }));

      const report = scanner.generateReport(processedFindings);
      setScanResults({
        ...report,
        findings: processedFindings // Keep findings as array for local scans
      });
      
      const { criticalIssues = 0, highIssues = 0, mediumIssues = 0, lowIssues = 0 } = report.summary || {};
      setSuccessMessage(
        `Scan complete! Found ${processedFindings.length} potential vulnerabilities ` +
        `(${criticalIssues} critical, ${highIssues} high, ${mediumIssues} medium, ${lowIssues} low)`
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleUrlScan = useCallback(async () => {
    if (!urlInput) return;
    
    if (!authManager.hasToken()) {
      setShowTokenDialog(true);
      return;
    }
    
    setScanning(true);
    setError(null);
    setScanResults(null);
    setUsedCache(false);
    
    try {
      const results = await scanRepository(urlInput);
      console.log('Scan results:', results);
      
      if (results.findings && results.summary) {
        setScanResults({
          findings: results.findings,
          summary: results.summary,
          rateLimit: results.rateLimit
        });
        setSuccessMessage(
          `Scan complete! Found ${results.summary.totalIssues} potential vulnerabilities ` +
          `(${results.summary.criticalIssues} critical, ${results.summary.highIssues} high, ` +
          `${results.summary.mediumIssues} medium, ${results.summary.lowIssues} low)`
        );
        setUsedCache(results.fromCache || false);
      } else {
        setSuccessMessage(`Found ${results.files.length} files in repository`);
      }
      
      // Show rate limit info
      if (results.rateLimit) {
        setRateLimitInfo(results.rateLimit);
      }
    } catch (err) {
      setError(err.message);
      if (err.status === 403) {
        setError('Rate limit exceeded. Please try again later.');
      }
    } finally {
      setScanning(false);
    }
  }, [urlInput]);

  const handleTokenSubmit = async (token) => {
    if (!token) return;

    setError(null);

    if (!authManager.isValidTokenFormat(token)) {
      setError('Invalid token format. Please ensure you\'ve copied the entire token.');
      return;
    }

    try {
      authManager.setToken(token);
      setGithubToken(token);
      setShowTokenDialog(false);
      
      // Only trigger scan if we have a URL
      if (urlInput) {
        await handleUrlScan();
      }
    } catch (error) {
      console.error('Token submission error:', error);
      setError(error.message);
      authManager.clearToken();
      setGithubToken('');
    }
  };

  return (
    <div className="p-8 bg-gradient-to-b from-blue-50 via-white to-blue-50 min-h-screen">
      <div className="max-w-4xl mx-auto">
        {/* HEADER */}
        <div className="text-center mb-12">
          <h1 className="inline-flex items-center text-4xl font-bold text-gray-900 tracking-tight mb-2">
            <Shield className="h-10 w-10 text-blue-600 mr-3 transform -rotate-6" />
            <span className="bg-gradient-to-r from-blue-600 to-blue-800 bg-clip-text text-transparent">
              SecurityLens
            </span>
          </h1>
          <p className="text-gray-600 mt-6 max-w-2xl mx-auto leading-relaxed">
            Scans code for security vulnerabilities including code injection, 
            authentication bypass, SQL injection, XSS, buffer issues, 
            sensitive data exposure, and more. Supports JavaScript, TypeScript, 
            Python, and other languages.
          </p>
        </div>

        {/* SCAN REPO */}
        <div className="bg-white p-8 rounded-xl shadow-lg mb-8 border border-gray-100 hover:border-blue-100 transition-colors">
          <h2 className="text-xl font-semibold text-gray-700 mb-6 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Scan Repository
          </h2>
          <div className="flex gap-4">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter GitHub repository URL"
              className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all hover:border-gray-400"
            />
            <button
              onClick={handleUrlScan}
              disabled={scanning || !urlInput}
              className={`px-6 py-3 rounded-lg text-white font-medium transition-all transform hover:scale-105 ${
                scanning || !urlInput
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 shadow-md'
              }`}
            >
              {scanning ? 'Scanning...' : 'Scan Repository'}
            </button>
          </div>
        </div>

        {/* SCAN LOCAL FILES */}
        <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-100 hover:border-blue-100 transition-colors">
          <h2 className="text-xl font-semibold text-gray-700 mb-6 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Scan Local Files
          </h2>
          <div className="flex justify-center">
            <input
              type="file"
              id="fileInput"
              multiple
              onChange={handleFileUpload}
              className="hidden"
            />
            <label
              htmlFor="fileInput"
              className="group inline-flex flex-col items-center justify-center px-6 py-8 
                       bg-gray-50 rounded-xl border-2 border-dashed border-gray-300 
                       cursor-pointer hover:bg-blue-50 hover:border-blue-300 transition-all 
                       focus:outline-none focus:ring-2 focus:ring-blue-500 w-full text-center"
            >
              <svg className="w-12 h-12 text-gray-400 group-hover:text-blue-500 transition-colors mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              <p className="text-gray-700 group-hover:text-gray-900 transition-colors font-medium">
                Drag and drop files here, or click to select files
              </p>
              <p className="text-sm text-gray-500 mt-2">
                Supported files: .js, .jsx, .ts, .tsx, .py, etc.
              </p>
            </label>
          </div>
        </div>

        {/* PROGRESS BAR */}
        {scanning && progress.total > 0 && (
          <div className="my-6">
            <div className="w-full bg-gray-300 rounded-full h-3 overflow-hidden">
              <div
                className="bg-blue-600 h-3 rounded-full transition-all duration-300"
                style={{ width: `${(progress.current / progress.total) * 100}%` }}
              />
            </div>
            <div className="text-sm text-gray-700 mt-2 text-center">
              {progress.current === progress.total 
                ? 'Processing results...' 
                : `Scanning file ${progress.current} of ${progress.total}`}
            </div>
          </div>
        )}

        {/* SUCCESS MESSAGE */}
        {successMessage && (
          <Alert className="my-4" variant="default">
            <AlertDescription>{successMessage}</AlertDescription>
          </Alert>
        )}

        {/* ERROR MESSAGE */}
        {error && (
          <Alert className="my-4" variant="error">
            <AlertDescription>
              <AlertTriangle className="h-4 w-4 inline-block mr-2" />
              {error}
            </AlertDescription>
          </Alert>
        )}

        {/* RATE LIMIT INFO */}
        {rateLimitInfo && rateLimitInfo.remaining < 10 && (
          <Alert className="my-4" variant="warning">
            <AlertDescription>
              Rate limit: {rateLimitInfo.remaining} requests remaining.
              Resets at {new Date(rateLimitInfo.reset * 1000).toLocaleTimeString()}
            </AlertDescription>
          </Alert>
        )}

        {/* SCAN RESULTS */}
        {scanResults && (
          <div className="mt-6">
            <ScanResults 
              results={scanResults}
              usedCache={usedCache}
              onRefreshRequest={handleUrlScan}
              scanning={scanning}
            />
          </div>
        )}

        {/* GITHUB TOKEN NOTICE (if none saved) */}
        {!githubToken && (
          <div className="bg-white p-6 rounded-lg shadow mt-6">
            <h2 className="text-lg font-semibold text-gray-700 mb-4">GitHub Access Token</h2>
            <p className="text-sm text-gray-600 mb-4">
              To scan repositories, you'll need a GitHub personal access token.
              This stays in your browser and is never sent to any server.
            </p>
            <input 
              type="password"
              placeholder="GitHub token"
              onChange={(e) => handleTokenSubmit(e.target.value)}
              className="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
            />
            <a 
              href="https://github.com/settings/tokens/new" 
              target="_blank"
              rel="noreferrer"
              className="text-sm text-blue-600 hover:underline mt-2 inline-block"
            >
              Generate a token
            </a>
          </div>
        )}
      </div>

      {/* TOKEN DIALOG */}
      <AlertDialog open={showTokenDialog} onClose={() => setShowTokenDialog(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <h2 className="text-lg font-semibold">GitHub Token Required</h2>
          </AlertDialogHeader>
          <div className="space-y-4">
            <div className="bg-blue-50 border border-blue-200 rounded p-3 text-sm">
              <strong>🔒 Security Note:</strong> Your token is stored only in your browser's local storage. 
              It never leaves your device and is not sent to any external servers.
            </div>
            <p className="text-sm text-gray-600">
              To scan GitHub repositories, you'll need a Personal Access Token. Here's how to get one:
            </p>
            <ol className="list-decimal list-inside space-y-2 text-sm">
              <li>
                Go to{' '}
                <a 
                  href="https://github.com/settings/tokens/new" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  GitHub Token Settings
                </a>
              </li>
              <li>Select either "Classic" or "Fine-grained" token</li>
              <li>Enable "repo" access permissions</li>
              <li>Generate and copy the token</li>
            </ol>
            <input
              type="password"
              placeholder="Paste your GitHub token here"
              className="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
              onChange={(e) => handleTokenSubmit(e.target.value)}
            />
          </div>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default ScannerUI;
