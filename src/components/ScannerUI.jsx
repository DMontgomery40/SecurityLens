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
  const [showTerms, setShowTerms] = useState(false);
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [showLicense, setShowLicense] = useState(false);
  const [showVulnList, setShowVulnList] = useState(false);

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
            <Shield className="h-10 w-10 text-blue-600 mr-3 transform -rotate-0" />
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
          
          {/* Info Button */}
          <button 
            onClick={() => setShowVulnList(true)} 
            className="mt-4 text-sm text-blue-600 hover:text-blue-800 transition-colors"
          >
            View Full List of Checks
          </button>
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
          <Alert className="my-4" variant={error.includes('Invalid GitHub URL') ? 'default' : 'error'}>
            <AlertDescription>
              {error.includes('Invalid GitHub URL') ? (
                <div className="space-y-2">
                  <p><AlertTriangle className="h-4 w-4 inline-block mr-2" />Please provide a valid GitHub repository URL in one of these formats:</p>
                  <ul className="list-disc pl-5 text-sm">
                    <li>https://github.com/username/repository</li>
                    <li>https://github.com/username/repository/tree/branch</li>
                    <li>https://github.com/username/repository/tree/branch/folder</li>
                  </ul>
                </div>
              ) : (
                <>
                  <AlertTriangle className="h-4 w-4 inline-block mr-2" />
                  {error}
                </>
              )}
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

      {/* Legal Footer */}
      <footer className="mt-8 border-t border-gray-200 pt-8 pb-4">
        <div className="max-w-4xl mx-auto space-y-4">
          {/* Warning Banner */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6 text-sm text-yellow-800">
            <p><strong>Beta Notice:</strong> SecurityLens is in active development. Please note:</p>
            <ul className="list-disc pl-5 mt-2 space-y-1">
              <li>Results may include false positives</li>
              <li>The dependency vulnerability and outdated dependency checkers are currently in development</li>
            </ul>
          </div>

          {/* Links */}
          <div className="flex justify-center space-x-6 text-sm text-gray-600">
            <button 
              onClick={() => setShowTerms(true)} 
              className="hover:text-blue-600 transition-colors"
            >
              Terms of Service
            </button>
            <button 
              onClick={() => setShowPrivacy(true)} 
              className="hover:text-blue-600 transition-colors"
            >
              Privacy Policy
            </button>
            <a 
              href="https://github.com/DMontgomery40/SecurityLens"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-blue-600 transition-colors"
            >
              GitHub
            </a>
            <button 
              onClick={() => setShowLicense(true)} 
              className="hover:text-blue-600 transition-colors"
            >
              License
            </button>
          </div>

          {/* Copyright */}
          <div className="text-center text-sm text-gray-500 mt-4">
            © {new Date().getFullYear()} David Montgomery. MIT License.
          </div>
        </div>
      </footer>
          {/* VULNERABILITY LIST POPUP */}
          <AlertDialog open={showVulnList} onClose={() => setShowVulnList(false)}>
            <AlertDialogContent>
              {/* Header + Close Button Row */}
              <div className="flex items-center justify-between mb-4">
                <AlertDialogHeader>
                  <h2 className="text-lg font-semibold">Full Vulnerability List</h2>
                </AlertDialogHeader>
                <button
                  className="text-gray-500 hover:text-gray-700 px-2 py-1"
                  onClick={() => setShowVulnList(false)}
                >
                  ✕
                </button>
              </div>

              {/* Scrollable table wrapper */}
              <div className="max-h-[60vh] overflow-auto border rounded-md">
                <table className="w-full text-left border-collapse">
                  <thead className="sticky top-0 bg-white shadow">
                    <tr className="border-b border-gray-300">
                      <th className="py-2 px-4 font-medium">Vulnerability</th>
                      <th className="py-2 px-4 font-medium">Description</th>
                      <th className="py-2 px-4 font-medium">Severity</th>
                      <th className="py-2 px-4 font-medium">CWE</th>
                    </tr>
                  </thead>
                  <tbody className="text-sm">

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Dangerous Code Execution</td>
                      <td className="py-2 px-4">
                        Dangerous code execution via <code>eval()</code> or Function constructor
                      </td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/95.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-95
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Command Injection</td>
                      <td className="py-2 px-4">Potential command injection vulnerability</td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/77.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-77
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Authentication Bypass</td>
                      <td className="py-2 px-4">Authentication bypass or missing authentication</td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/306.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-306
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Hardcoded Credentials</td>
                      <td className="py-2 px-4">Hardcoded credentials detected</td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/798.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-798
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">SQL Injection</td>
                      <td className="py-2 px-4">Potential SQL injection vulnerability</td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/89.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-89
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Cross-site Scripting (XSS)</td>
                      <td className="py-2 px-4">Cross-site scripting vulnerability</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/79.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-79
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">NoSQL Injection</td>
                      <td className="py-2 px-4">Potential NoSQL injection vulnerability</td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/943.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-943
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Weak Cryptographic Hash</td>
                      <td className="py-2 px-4">Use of weak cryptographic hash function</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/326.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-326
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Deprecated Cryptographic Functions</td>
                      <td className="py-2 px-4">Use of deprecated cryptographic functions</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/927.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-927
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Unsafe Buffer Allocation</td>
                      <td className="py-2 px-4">Unsafe buffer allocation</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/119.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-119
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Memory Leak in Timer/Interval</td>
                      <td className="py-2 px-4">Potential memory leak in timer/interval</td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/401.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-401
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Sensitive Data Exposure</td>
                      <td className="py-2 px-4">Sensitive data exposure</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/200.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-200
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Insecure Data Transmission</td>
                      <td className="py-2 px-4">Potential insecure data transmission</td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/319.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-319
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Sensitive Information in Errors</td>
                      <td className="py-2 px-4">
                        Potential sensitive information in error messages
                      </td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/209.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-209
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Insecure Direct Object Reference (IDOR)</td>
                      <td className="py-2 px-4">
                        Potential Insecure Direct Object Reference (IDOR)
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/639.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-639
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Improper Authorization Checks</td>
                      <td className="py-2 px-4">
                        Improper authorization checks allowing unauthorized access
                      </td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/306.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-306
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Path Traversal</td>
                      <td className="py-2 px-4">Potential path traversal vulnerability</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/23.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-23
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Unsanitized Input Usage</td>
                      <td className="py-2 px-4">
                        Unsanitized user input used in sensitive operations
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/932.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-932
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Open Redirect</td>
                      <td className="py-2 px-4">Potential open redirect vulnerability</td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/601.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-601
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Resource Leak</td>
                      <td className="py-2 px-4">
                        Potential resource leak due to synchronous file operations
                      </td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/399.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-399
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Session Fixation</td>
                      <td className="py-2 px-4">
                        Potential session fixation vulnerability allowing attacker to set session ID
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/384.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-384
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Insecure Session Storage</td>
                      <td className="py-2 px-4">
                        Insecure session storage without secure flags
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/925.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-925
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Server-Side Request Forgery (SSRF)</td>
                      <td className="py-2 px-4">
                        Potential SSRF vulnerability from user-supplied input in request calls
                      </td>
                      <td className="py-2 px-4">CRITICAL</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/918.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-918
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Insecure API Setup</td>
                      <td className="py-2 px-4">
                        Potential insecure API setup without proper authentication middleware
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/921.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-921
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">JWT in URL</td>
                      <td className="py-2 px-4">
                        JWT token present in URL instead of headers
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/922.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-922
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Token in URL</td>
                      <td className="py-2 px-4">
                        Authentication token present in URL parameters
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/923.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-923
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Weak Rate Limiting</td>
                      <td className="py-2 px-4">
                        Potentially weak rate limiting configuration in API setup
                      </td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/924.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-924
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Missing or Misconfigured CORS</td>
                      <td className="py-2 px-4">Missing or misconfigured CORS in API setup</td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/925.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-925
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Insecure Middleware Setup</td>
                      <td className="py-2 px-4">Insecure middleware setup allowing unauthorized access</td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/926.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-926
                        </a>
                      </td>
                    </tr>

                    <tr className="border-b border-gray-100">
                      <td className="py-2 px-4">Vulnerable Dependencies</td>
                      <td className="py-2 px-4">
                        Vulnerable dependencies detected in <code>package.json</code>
                      </td>
                      <td className="py-2 px-4">HIGH</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/925.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-925
                        </a>
                      </td>
                    </tr>

                    <tr>
                      <td className="py-2 px-4">Outdated Dependencies</td>
                      <td className="py-2 px-4">
                        Outdated dependencies detected in <code>package.json</code>
                      </td>
                      <td className="py-2 px-4">MEDIUM</td>
                      <td className="py-2 px-4">
                        <a
                          href="https://cwe.mitre.org/data/definitions/926.html"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 underline"
                        >
                          CWE-926
                        </a>
                      </td>
                    </tr>

                  </tbody>
                </table>
              </div>
            </AlertDialogContent>
          </AlertDialog>


      {/* Privacy Dialog */}
      <AlertDialog open={showPrivacy} onClose={() => setShowPrivacy(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <h2 className="text-lg font-semibold">Privacy Policy</h2>
          </AlertDialogHeader>
          <div className="space-y-4 text-sm">
            <h3 className="font-medium">Data Collection</h3>
            <p>
              SecurityLens is designed with privacy in mind. We do not collect, store, or transmit:
            </p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Your GitHub tokens (stored only in your browser)</li>
              <li>Your source code</li>
              <li>Scan results</li>
              <li>Personal information</li>
            </ul>
            <h3 className="font-medium">Local Storage</h3>
            <p>
              The only data stored locally in your browser is your GitHub token, if you choose to provide one.
              You can clear this at any time by clearing your browser data.
            </p>
            <h3 className="font-medium">Third-Party Services</h3>
            <p>
              We use GitHub's API for repository scanning. Your interactions with GitHub are subject to their privacy policy.
            </p>
          </div>
        </AlertDialogContent>
      </AlertDialog>

      {/* Terms of Service Dialog */}
      <AlertDialog open={showTerms} onClose={() => setShowTerms(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <h2 className="text-lg font-semibold">Terms of Service</h2>
          </AlertDialogHeader>
          <div className="space-y-4 text-sm">
            <h3 className="font-medium">1. Acceptance of Terms</h3>
            <p>
              By accessing and using SecurityLens, you agree to be bound by these Terms of Service.
            </p>

            <h3 className="font-medium">2. Service Description</h3>
            <p>
              SecurityLens is a code scanning tool that helps identify potential security vulnerabilities
              in source code. The service is provided "as is" and "as available".
            </p>

            <h3 className="font-medium">3. Use of Service</h3>
            <ul className="list-disc pl-5 space-y-2">
              <li>You must use the service in compliance with all applicable laws</li>
              <li>You are responsible for maintaining the security of your GitHub tokens</li>
              <li>You agree not to misuse or attempt to circumvent the service's limitations</li>
            </ul>

            <h3 className="font-medium">4. Limitations of Liability</h3>
            <p>
              SecurityLens and its creators are not liable for any damages arising from the use
              or inability to use the service. Scan results are provided without warranty of any kind.
            </p>

            <h3 className="font-medium">5. Changes to Terms</h3>
            <p>
              We reserve the right to modify these terms at any time. Continued use of the service
              constitutes acceptance of modified terms.
            </p>
          </div>
        </AlertDialogContent>
      </AlertDialog>

      {/* License Dialog */}
      <AlertDialog open={showLicense} onClose={() => setShowLicense(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <h2 className="text-lg font-semibold">MIT License</h2>
          </AlertDialogHeader>
          <div className="space-y-4 text-sm">
            <p>Copyright (c) {new Date().getFullYear()} David Montgomery</p>
            
            <p>
              Permission is hereby granted, free of charge, to any person obtaining a copy
              of this software and associated documentation files (the "Software"), to deal
              in the Software without restriction, including without limitation the rights
              to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
              copies of the Software, and to permit persons to whom the Software is
              furnished to do so, subject to the following conditions:
            </p>

            <p>
              The above copyright notice and this permission notice shall be included in all
              copies or substantial portions of the Software.
            </p>

            <p className="text-xs">
              THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
              IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
              FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
              AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
              LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
              OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
              SOFTWARE.
            </p>

            <div className="pt-4 border-t">
              <p>
                Want to contribute? Visit the{' '}
                <a 
                  href="https://github.com/DMontgomery40/SecurityLens" 
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  GitHub repository
                </a>
                {' '}to:
              </p>
              <ul className="list-disc pl-5 mt-2">
                <li>Report issues</li>
                <li>Submit pull requests</li>
                <li>View the source code</li>
              </ul>
            </div>
          </div>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default ScannerUI;
