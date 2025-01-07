import React, { useState, useCallback, useEffect } from 'react';
import { AlertTriangle, Shield } from 'lucide-react';
import { Alert, AlertDescription } from './ui/alert';
import VulnerabilityScanner, { scanRepositoryLocally } from '../lib/scanner';
import ScanResults from './ScanResults';
import { authManager } from '../lib/githubAuth';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader
} from './ui/alert-dialog';
import { patterns } from '../lib/patterns'; // Ensure patterns are exported from patterns.index.js

const ScannerUI = () => {
  // State Management
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
  const [severityStats, setSeverityStats] = useState({
    CRITICAL: { uniqueCount: 0, instanceCount: 0 },
    HIGH: { uniqueCount: 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: 0, instanceCount: 0 },
    LOW: { uniqueCount: 0, instanceCount: 0 }
  });
  const [viewMode, setViewMode] = useState('type');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [showBackToTop, setShowBackToTop] = useState(false);
  const [filteredByType, setFilteredByType] = useState([]);
  const [filteredByFile, setFilteredByFile] = useState([]);

  // *** Added: Firmware/Binary Analysis State ***
  const [includeFirmware, setIncludeFirmware] = useState(false);
  const [firmwareMessage, setFirmwareMessage] = useState('');

  // Handler for Local File Upload
  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setProgress({ current: 0, total: files.length });
    setFirmwareMessage(''); // Reset firmware message

    try {
      const scanner = new VulnerabilityScanner({
        onProgress: (current, total) => {
          setProgress({ current, total });
        }
      });

      const results = await scanner.scanLocalFiles(files);
      setScanResults(results);
      setSeverityStats({
        CRITICAL: { uniqueCount: results.summary.criticalIssues, instanceCount: results.summary.criticalInstances },
        HIGH: { uniqueCount: results.summary.highIssues, instanceCount: results.summary.highInstances },
        MEDIUM: { uniqueCount: results.summary.mediumIssues, instanceCount: results.summary.mediumInstances },
        LOW: { uniqueCount: results.summary.lowIssues, instanceCount: results.summary.lowInstances }
      });
      setSuccessMessage(`Successfully scanned ${files.length} files`);
      
      // *** Added: Firmware Analysis Placeholder ***
      if (includeFirmware) {
        setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'Error scanning files');
    } finally {
      setScanning(false);
    }
  };

  // Handler for Repository Scan
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
    setFirmwareMessage(''); // Reset firmware message

    try {
      const scanner = new VulnerabilityScanner({
        onProgress: (progress) => {
          setProgress(progress);
        }
      });

      const results = await scanRepositoryLocally(urlInput);
      console.log('Scan results:', results);

      if (results.findings && results.summary) {
        setScanResults(results);
        setSeverityStats({
          CRITICAL: { uniqueCount: results.summary.criticalIssues || 0, instanceCount: results.summary.criticalInstances || 0 },
          HIGH: { uniqueCount: results.summary.highIssues || 0, instanceCount: results.summary.highInstances || 0 },
          MEDIUM: { uniqueCount: results.summary.mediumIssues || 0, instanceCount: results.summary.mediumInstances || 0 },
          LOW: { uniqueCount: results.summary.lowIssues || 0, instanceCount: results.summary.lowInstances || 0 }
        });

        setSuccessMessage(
          `Scan complete! Found ${results.summary.totalIssues} potential vulnerabilities ` +
            `(${results.summary.criticalIssues} critical, ${results.summary.highIssues} high, ` +
            `${results.summary.mediumIssues} medium, ${results.summary.lowIssues} low)`
        );
        setUsedCache(results.fromCache || false);
        
        // *** Added: Firmware Analysis Placeholder ***
        if (includeFirmware) {
          setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
        }
      } else {
        setSuccessMessage(`Found ${results.files.length} files in repository`);
      }

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
  }, [urlInput, includeFirmware]);

  // Handler for GitHub Token Submission
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

      // Trigger scan if URL is present
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

  // Scroll to top handler
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Handle scroll for back to top button
  useEffect(() => {
    const handleScroll = () => {
      setShowBackToTop(window.scrollY > 300);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Filter results based on search and severity
  useEffect(() => {
    if (!scanResults?.findings) return;

    const filtered = scanResults.findings.filter(finding => {
      const matchesSearch = searchQuery.toLowerCase() === '' ||
        finding.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        finding.files.some(file => file.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesSeverity = activeSeverity === 'ALL' || finding.severity === activeSeverity;

      return matchesSearch && matchesSeverity;
    });

    // Group by type
    setFilteredByType(filtered);

    // Group by file
    const byFile = filtered.reduce((acc, finding) => {
      finding.files.forEach(file => {
        if (!acc[file]) acc[file] = [];
        acc[file].push(finding);
      });
      return acc;
    }, {});

    setFilteredByFile(Object.entries(byFile).map(([fileName, vulns]) => ({
      fileName,
      vulns
    })));
  }, [scanResults, searchQuery, activeSeverity]);

  return (
    <div className="p-6 bg-gray-900 text-white min-h-screen">
      <div className="max-w-4xl mx-auto">
        {/* HEADER */}
        <div className="text-center mb-10">
          <h1 className="inline-flex items-center text-4xl font-bold tracking-tight mb-2">
            <Shield className="h-10 w-10 text-blue-400 mr-3" />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-600">
              SecurityLens
            </span>
          </h1>
          
          <p className="text-gray-300 mb-4 max-w-2xl mx-auto leading-relaxed">
            It's sort of like if semgrep-lite and walkbin-lite had a baby.
          </p>
          
          <hr className="my-4 border-gray-700" />
          
          <p className="text-gray-300 mb-4 max-w-2xl mx-auto leading-relaxed">
            Just more attractive and easy going, with no upselling, no logins,
            no cookies, no ads, no tracking, no downloads, and no uploads.
          </p>
          
          <hr className="my-4 border-gray-700" />

          {/* GitHub Link */}
          <a
            href="https://github.com/DMontgomery40/SecurityLens"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 underline hover:text-purple-400 transition-colors"
          >
            Please Contribute Your Knowledge
          </a>
          <br />

          {/* View Checks Button */}
          <button
            onClick={() => setShowVulnList(true)}
            className="mt-4 text-sm text-blue-400 hover:text-purple-400 transition-colors"
          >
            View Full List of Checks
          </button>
        </div>

        {/* SCAN REPO */}
        <div className="bg-gray-800 p-8 rounded-xl shadow-lg mb-8 border border-gray-700">
          <h2 className="text-xl font-semibold text-gray-200 mb-6 flex items-center">
            <svg
              className="w-5 h-5 mr-2 text-blue-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M13 10V3L4 14h7v7l9-11h-7z"
              />
            </svg>
            Scan Repository
          </h2>
          
          {/* Responsive Flex Container */}
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Input Field */}
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter GitHub repository URL"
              className="w-full px-4 py-3 border border-gray-600 rounded-lg bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            
            {/* Button */}
            <button
              onClick={handleUrlScan}
              disabled={scanning || !urlInput}
              className={`w-full sm:w-auto px-6 py-3 rounded-lg text-white font-medium transition-all transform hover:scale-105 ${
                scanning || !urlInput
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 shadow-md'
              }`}
            >
              {scanning ? 'Scanning...' : 'Scan Repository'}
            </button>
          </div>
        </div>

        {/* SCAN LOCAL FILES */}
        <div className="bg-gray-800 p-8 rounded-xl shadow-lg border border-gray-700 mb-8">
          <h2 className="text-xl font-semibold text-gray-200 mb-6 flex items-center">
            <svg
              className="w-5 h-5 mr-2 text-blue-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"
              />
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
              className="group inline-flex flex-col items-center justify-center px-3 py-4 
                       bg-gray-700 rounded-md border-2 border-dashed border-gray-600 
                       cursor-pointer hover:bg-gray-600 transition-all 
                       focus:outline-none focus:ring-2 focus:ring-blue-500 w-full text-center"
            >
              <svg
                className="w-12 h-12 text-gray-400 group-hover:text-blue-400 transition-colors mb-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
              <p className="text-gray-300 group-hover:text-gray-100 font-medium">
                Drag and drop files here, or click to select files
              </p>
              <p className="text-sm text-gray-500 mt-2">
                Supported files: .js, .jsx, .ts, .tsx, .py, etc.
              </p>
            </label>
          </div>
        </div>

        {/* *** Added: Firmware/Binary Analysis Section *** */}
        <div className="bg-gray-800 p-8 rounded-xl shadow-lg border border-gray-700 mb-8">
          <h2 className="text-xl font-semibold text-gray-200 mb-6 flex items-center">
            <svg
              className="w-5 h-5 mr-2 text-blue-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 4v16m8-8H4"
              />
            </svg>
            Scan Firmware/Binary <span className="text-xs text-yellow-400">(Coming Soon!)</span>
          </h2>
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Firmware Upload Field */}
            <input
              type="file"
              id="firmwareInput"
              accept=".bin,.fw,.img,.hex" // Specify firmware file types
              onChange={(e) => {
                if (includeFirmware) {
                  setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
                }
              }}
              className="hidden"
            />
            <label
              htmlFor="firmwareInput"
              className={`group inline-flex flex-col items-center justify-center px-3 py-4 
                         bg-gray-700 rounded-md border-2 border-dashed border-gray-600 
                         cursor-pointer hover:bg-gray-600 transition-all 
                         focus:outline-none focus:ring-2 focus:ring-blue-500 w-full text-center ${
                           includeFirmware ? '' : 'opacity-50 cursor-not-allowed'
                         }`}
              onClick={(e) => {
                if (!includeFirmware) {
                  e.preventDefault();
                }
              }}
            >
              <svg
                className="w-12 h-12 text-gray-400 group-hover:text-blue-400 transition-colors mb-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M12 4v16m8-8H4"
                />
              </svg>
              <p className="text-gray-300 group-hover:text-gray-100 font-medium">
                Drag and drop firmware files here, or click to select files
              </p>
              <p className="text-sm text-gray-500 mt-2">
                Supported files: .bin, .fw, .img, .hex
              </p>
            </label>
          </div>
          {/* Display Coming Soon Message */}
          {firmwareMessage && (
            <Alert className="my-4" variant="default">
              <AlertDescription>{firmwareMessage}</AlertDescription>
            </Alert>
          )}
        </div>

        {/* PROGRESS BAR */}
        {scanning && progress.total > 0 && (
          <div className="my-6">
            <div className="w-full bg-gray-600 rounded-full h-3 overflow-hidden">
              <div
                className="bg-blue-400 h-3 rounded-full transition-all duration-300"
                style={{ width: `${(progress.current / progress.total) * 100}%` }}
              />
            </div>
            <div className="text-sm text-gray-300 mt-2 text-center">
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
          <Alert
            className="my-4"
            variant={error.includes('Invalid GitHub URL') ? 'default' : 'error'}
          >
            <AlertDescription>
              {error.includes('Invalid GitHub URL') ? (
                <div className="space-y-2">
                  <p>
                    <AlertTriangle className="h-4 w-4 inline-block mr-2" />
                    Please provide a valid GitHub repository URL in one of these formats:
                  </p>
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
              viewMode={viewMode}
              setViewMode={setViewMode}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              activeSeverity={activeSeverity}
              setActiveSeverity={setActiveSeverity}
              severityStats={severityStats}
              filteredByType={filteredByType}
              filteredByFile={filteredByFile}
              usedCache={usedCache}
              scanning={scanning}
              onRefreshRequest={handleUrlScan}
              showBackToTop={showBackToTop}
              scrollToTop={scrollToTop}
              includeFirmware={includeFirmware} // *** Added: Pass includeFirmware to ScanResults ***
            />
            {/* Display Firmware Coming Soon Message */}
            {firmwareMessage && (
              <Alert className="my-4" variant="default">
                <AlertDescription>{firmwareMessage}</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {/* GITHUB TOKEN NOTICE */}
        {!githubToken && (
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
        )}
      </div>

      {/* TOKEN DIALOG */}
      <AlertDialog open={showTokenDialog} onClose={() => setShowTokenDialog(false)}>
        <AlertDialogContent className="bg-gray-900 border border-gray-700">
          <AlertDialogHeader>
            <h2 className="text-lg font-semibold text-gray-100">GitHub Token Required</h2>
          </AlertDialogHeader>
          <div className="space-y-4">
            <div className="bg-blue-900/50 border border-blue-700 rounded p-3 text-sm text-blue-100">
              <strong>🔒 Security Note:</strong> Your token is stored only in your
              browser's local storage. It never leaves your device and is not sent
              to any external servers.
            </div>
            <p className="text-sm text-gray-300">
              To scan GitHub repositories, you'll need a Personal Access Token. Here's how to get one:
            </p>
            <ol className="list-decimal list-inside space-y-2 text-sm text-gray-300">
              <li>
                Go to{' '}
                <a
                  href="https://github.com/settings/tokens/new"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  GitHub Token Settings
                </a>
              </li>
              <li>Select "Classic" or "Fine-grained" token</li>
              <li>Enable "repo" access permissions</li>
              <li>Generate and copy the token</li>
            </ol>
            <input
              type="password"
              placeholder="Paste your GitHub token here"
              className="w-full px-4 py-2 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 bg-gray-800 text-gray-100"
              onChange={(e) => handleTokenSubmit(e.target.value)}
            />
          </div>
        </AlertDialogContent>
      </AlertDialog>

      {/* Legal Footer */}
      <footer className="mt-8 border-t border-gray-700 pt-8 pb-4 bg-gray-900">
        <div className="max-w-4xl mx-auto space-y-4">
          {/* Warning Banner */}
          <div className="bg-yellow-900/50 border border-yellow-600/50 rounded-lg p-4 mb-6 text-sm text-yellow-200">
            <p>
              <strong>Beta Notice:</strong> SecurityLens is in active development. Please note:
            </p>
            <ul className="list-disc pl-5 mt-2 space-y-1">
              <li>Results may include false positives</li>
              <li>The dependency vulnerability and outdated dependency checkers are currently in development</li>
            </ul>
          </div>

          {/* Links */}
          <div className="flex justify-center space-x-6 text-sm text-gray-300">
            <button
              onClick={() => setShowTerms(true)}
              className="hover:text-blue-400 transition-colors"
            >
              Terms of Service
            </button>
            <button
              onClick={() => setShowPrivacy(true)}
              className="hover:text-blue-400 transition-colors"
            >
              Privacy Policy
            </button>
            <a
              href="https://github.com/DMontgomery40/SecurityLens"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-blue-400 transition-colors"
            >
              GitHub
            </a>
            <button
              onClick={() => setShowLicense(true)}
              className="hover:text-blue-400 transition-colors"
            >
              License
            </button>
          </div>

          {/* Copyright */}
          <div className="text-center text-sm text-gray-400 mt-4">
            &copy; {new Date().getFullYear()} David Montgomery. MIT License.
          </div>
        </div>
      </footer>

      {/* VULNERABILITY LIST POPUP */}
      <AlertDialog open={showVulnList} onClose={() => setShowVulnList(false)}>
        <AlertDialogContent>
          <div className="flex items-center justify-between mb-4">
            <AlertDialogHeader>
              <h2 className="text-lg font-semibold">Full Vulnerability List</h2>
            </AlertDialogHeader>
            <button
              className="text-gray-300 hover:text-gray-100 px-2 py-1"
              onClick={() => setShowVulnList(false)}
            >
              &times;
            </button>
          </div>

          {/* Scrollable Table */}
          <div className="max-h-[60vh] overflow-auto border rounded-md">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="border-b border-gray-700">
                  <th className="py-2 px-4 font-medium text-gray-200">Vulnerability</th>
                  <th className="py-2 px-4 font-medium text-gray-200">Description</th>
                  <th className="py-2 px-4 font-medium text-gray-200">Severity</th>
                  <th className="py-2 px-4 font-medium text-gray-200">CWE</th>
                </tr>
              </thead>
              <tbody className="text-sm text-gray-300">
                {/* Example Rows */}
                <tr className="border-b border-gray-700">
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
                      className="text-blue-400 underline"
                    >
                      CWE-95
                    </a>
                  </td>
                </tr>
                <tr className="border-b border-gray-700">
                  <td className="py-2 px-4">Command Injection</td>
                  <td className="py-2 px-4">Potential command injection vulnerability</td>
                  <td className="py-2 px-4">CRITICAL</td>
                  <td className="py-2 px-4">
                    <a
                      href="https://cwe.mitre.org/data/definitions/77.html"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 underline"
                    >
                      CWE-77
                    </a>
                  </td>
                </tr>
                {/* Dynamically Generate Rows from patterns */}
                {Object.entries(patterns).map(([key, pattern]) => (
                  <tr key={key} className="border-b border-gray-700">
                    <td className="py-2 px-4">{key.replace(/([A-Z])/g, ' $1').trim()}</td>
                    <td className="py-2 px-4">{pattern.description}</td>
                    <td className="py-2 px-4">{pattern.severity}</td>
                    <td className="py-2 px-4">
                      {pattern.cwe ? (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${pattern.cwe}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 underline"
                        >
                          CWE-{pattern.cwe}
                        </a>
                      ) : (
                        'N/A'
                      )}
                    </td>
                  </tr>
                ))}
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
            <p>&copy; {new Date().getFullYear()} David Montgomery</p>
            
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
                  className="text-blue-400 hover:underline"
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
