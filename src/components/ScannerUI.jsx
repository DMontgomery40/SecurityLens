import React, { useState, useCallback, useEffect } from 'react';
import { AlertTriangle, Shield } from 'lucide-react';
import { Alert, AlertDescription } from './ui/alert';
import VulnerabilityScanner, { scanRepositoryLocally } from '../lib/scanner';
import ScanResults from './ScanResults';
import { authManager } from '../lib/githubAuth';
import { scanWebPage } from '../lib/apiClient.js';
import {        
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader
} from './ui/alert-dialog';
import { patterns } from '../lib/patterns'; // Ensure patterns are exported

const patternCategories = {
  CRITICAL_EXECUTION: 'Critical Execution'
};

const ScannerUI = () => {
  // ------------------------------------------------------------------
  // Global State
  // ------------------------------------------------------------------
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

  // ------------------------------------------------------------------
  // Firmware / Binary State
  // ------------------------------------------------------------------
  const [includeFirmware, setIncludeFirmware] = useState(false);
  const [firmwareMessage, setFirmwareMessage] = useState('');

  // ------------------------------------------------------------------
  // File Upload (Local)
  // ------------------------------------------------------------------
  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setProgress({ current: 0, total: files.length });
    setFirmwareMessage('');

    try {
      const scanner = new VulnerabilityScanner({
        onProgress: (current, total) => {
          setProgress({ current, total });
        }
      });

      const results = await scanner.scanLocalFiles(files);
      setScanResults(results);

      setSeverityStats({
        CRITICAL: {
          uniqueCount: results.summary.criticalIssues,
          instanceCount: results.summary.criticalInstances
        },
        HIGH: {
          uniqueCount: results.summary.highIssues,
          instanceCount: results.summary.highInstances
        },
        MEDIUM: {
          uniqueCount: results.summary.mediumIssues,
          instanceCount: results.summary.mediumInstances
        },
        LOW: {
          uniqueCount: results.summary.lowIssues,
          instanceCount: results.summary.lowInstances
        }
      });

      setSuccessMessage(`Successfully scanned ${files.length} files`);

      // Firmware placeholder
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

  // ------------------------------------------------------------------
  // GitHub Repo Scan
  // ------------------------------------------------------------------
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
    setFirmwareMessage('');

    try {
      const results = await scanRepositoryLocally(urlInput);
      console.log('Scan results:', results);

      if (results.findings && results.summary) {
        setScanResults(results);
        setSeverityStats({
          CRITICAL: {
            uniqueCount: results.summary.criticalIssues || 0,
            instanceCount: results.summary.criticalInstances || 0
          },
          HIGH: {
            uniqueCount: results.summary.highIssues || 0,
            instanceCount: results.summary.highInstances || 0
          },
          MEDIUM: {
            uniqueCount: results.summary.mediumIssues || 0,
            instanceCount: results.summary.mediumInstances || 0
          },
          LOW: {
            uniqueCount: results.summary.lowIssues || 0,
            instanceCount: results.summary.lowInstances || 0
          }
        });

        setSuccessMessage(
          `Scan complete! Found ${results.summary.totalIssues} potential vulnerabilities ` +
          `(${results.summary.criticalIssues} critical, ` +
          `${results.summary.highIssues} high, ` +
          `${results.summary.mediumIssues} medium, ` +
          `${results.summary.lowIssues} low)`
        );

        setUsedCache(results.fromCache || false);

        if (includeFirmware) {
          setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
        }
      } else {
        // Possibly the repo was empty or something else
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

  // ------------------------------------------------------------------
  // Website Scan (HTML + Scripts)
  // ------------------------------------------------------------------
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [protocol, setProtocol] = useState('https');

  const normalizeUrl = (url) => {
    if (!url) return '';
    
    // Remove any existing protocol
    let cleanUrl = url.replace(/^(https?:\/\/)/, '');
    
    // Remove any trailing slashes
    cleanUrl = cleanUrl.replace(/\/+$/, '');
    
    return `${protocol}://${cleanUrl}`;
  };

  const handleWebsiteScan = async (url) => {
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setProgress({ current: 0, total: 0 });
    setFirmwareMessage('');
    setScanning(true);

    try {
      // Basic URL validation
      const urlPattern = /^(https?:\/\/)?[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]*)?$/;
      if (!urlPattern.test(url)) {
        throw new Error('Please enter a valid website URL');
      }

      // Call the function that hits your Netlify endpoint
      const data = await scanWebPage(url);

      // If your endpoint returns something like: { report: {...}, scriptsScanned: N, etc. }
      setScanResults(data.report || null);

      // If there's a summary with vulnerabilities, handle them similarly
      if (data.report?.findings && data.report.summary) {
        const { summary } = data.report;
        setSeverityStats({
          CRITICAL: {
            uniqueCount: summary.criticalIssues || 0,
            instanceCount: summary.criticalInstances || 0
          },
          HIGH: {
            uniqueCount: summary.highIssues || 0,
            instanceCount: summary.highInstances || 0
          },
          MEDIUM: {
            uniqueCount: summary.mediumIssues || 0,
            instanceCount: summary.mediumInstances || 0
          },
          LOW: {
            uniqueCount: summary.lowIssues || 0,
            instanceCount: summary.lowInstances || 0
          }
        });
        setSuccessMessage(
          `Website scan complete! Found ${summary.totalIssues || 0} potential vulnerabilities.`
        );
      } else {
        setSuccessMessage('Website scan completed, but no vulnerabilities reported.');
      }
    } catch (err) {
      console.error('Website scan error:', err);
      setError(err.message || 'Error scanning website. Please check the URL and try again.');
    } finally {
      setScanning(false);
    }
  };

  // ------------------------------------------------------------------
  // Handle GitHub Token Submission
  // ------------------------------------------------------------------
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

      // If user was trying to scan a repo, do it now that we have a token
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

  // ------------------------------------------------------------------
  // Scroll for Back to Top button
  // ------------------------------------------------------------------
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    const handleScroll = () => {
      setShowBackToTop(window.scrollY > 300);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // ------------------------------------------------------------------
  // Filter results by search & severity
  // ------------------------------------------------------------------
  useEffect(() => {
    if (!scanResults?.findings) return;

    const filtered = scanResults.findings.filter((finding) => {
      const matchesSearch =
        searchQuery.toLowerCase() === '' ||
        finding.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        finding.files.some((file) =>
          file.toLowerCase().includes(searchQuery.toLowerCase())
        );

      const matchesSeverity =
        activeSeverity === 'ALL' || finding.severity === activeSeverity;

      return matchesSearch && matchesSeverity;
    });

    // Group by type
    setFilteredByType(filtered);

    // Group by file
    const byFile = filtered.reduce((acc, finding) => {
      finding.files.forEach((file) => {
        if (!acc[file]) acc[file] = [];
        acc[file].push(finding);
      });
      return acc;
    }, {});

    setFilteredByFile(
      Object.entries(byFile).map(([fileName, vulns]) => ({
        fileName,
        vulns
      }))
    );
  }, [scanResults, searchQuery, activeSeverity]);

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------
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

          <p className="text-gray-300 mb-3 max-w-xl mx-auto leading-relaxed">
            An education tool for the next generation of cybersecurity professionals.
          </p>

          <p className="text-gray-300 mb-3 max-w-xl mx-auto leading-relaxed">
            Simply drag/drag or copy/paste to scan GitHub repositories,
            or upload local files, to scan for web vulnerabilities and binary/firmware vulnerabilities.
            <br />
          </p>

          {/* We move <hr> OUTSIDE the <p> to avoid the nesting warning */}
          <hr className="my-4 border-gray-700" />
          <p className="text-gray-300 mb-3 max-w-xl mx-auto leading-relaxed">
            <strong>
              No upselling, no registration, no logins, no cookies, no ads, no tracking,
              no downloads, and no uploads.
            </strong>
          </p>

          <hr className="my-4 border-gray-700" />

          <a
            href="https://github.com/DMontgomery40/SecurityLens"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 underline hover:text-purple-400 transition-colors"
          >
            Please Contribute Your Knowledge
          </a>
          <br />
          <button
            onClick={() => setShowVulnList(true)}
            className="mt-4 text-sm text-blue-400 hover:text-purple-400 transition-colors"
          >
            View Current Vulnerability List
          </button>
        </div>

        {/* SCAN REPOSITORY */}
        <div className="bg-gray-800/50 p-4 rounded-lg mb-4">
          <h2 className="text-lg font-semibold text-gray-200 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Scan Repository
          </h2>
          <div className="flex gap-2">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter GitHub repository URL"
              className="flex-1 px-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg 
                        focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleUrlScan}
              disabled={scanning || !urlInput}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 
                        disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Scan Repository
            </button>
          </div>
        </div>

        {/* SCAN WEBSITE */}
        <div className="bg-gray-800/50 p-4 rounded-lg mb-4">
          <h2 className="text-lg font-semibold text-gray-200 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="9" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v18M3 12h18" />
            </svg>
            Scan Website (HTML + Scripts)
          </h2>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              {/* Protocol Toggle */}
              <div className="flex items-center bg-gray-700 rounded-lg p-1">
                <button
                  onClick={() => setProtocol('https')}
                  className={`px-3 py-1 rounded-md text-sm transition-colors ${
                    protocol === 'https'
                      ? 'bg-blue-500 text-white'
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  HTTPS
                </button>
                <button
                  onClick={() => setProtocol('http')}
                  className={`px-3 py-1 rounded-md text-sm transition-colors ${
                    protocol === 'http'
                      ? 'bg-blue-500 text-white'
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  HTTP
                </button>
              </div>
              
              {/* URL Input with Protocol Display */}
              <div className="flex-1 relative">
                <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
                  {protocol}://
                </div>
                <input
                  type="text"
                  value={websiteUrl}
                  onChange={(e) => setWebsiteUrl(e.target.value.replace(/^(https?:\/\/)/, ''))}
                  placeholder="example.com"
                  className="w-full pl-[4.5rem] pr-4 py-2 bg-gray-700/50 border border-gray-600 rounded-lg 
                            focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              
              <button
                onClick={() => {
                  const normalizedUrl = normalizeUrl(websiteUrl);
                  if (!websiteUrl.trim()) {
                    setError('Please enter a website URL');
                    return;
                  }
                  handleWebsiteScan(normalizedUrl);
                }}
                disabled={scanning || !websiteUrl.trim()}
                className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 
                          disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Scan Website
              </button>
            </div>
            
            {/* URL Validation Message */}
            {websiteUrl && !websiteUrl.match(/^[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}/) && (
              <div className="text-yellow-400 text-sm flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                        d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Please enter a valid domain (e.g., example.com)
              </div>
            )}
          </div>
        </div>

        {/* SCAN LOCAL FILES */}
        <div className="bg-gray-800/50 p-4 rounded-lg mb-4">
          <h2 className="text-lg font-semibold text-gray-200 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 7h5l2 2h11v10H3z" />
            </svg>
            Scan Local Files
          </h2>
          <div className="border-2 border-dashed border-gray-600 rounded-lg p-4 text-center">
            <input
              type="file"
              id="fileInput"
              multiple
              onChange={handleFileUpload}
              className="hidden"
            />
            <label
              htmlFor="fileInput"
              className="block cursor-pointer"
            >
              <p className="text-gray-300">Drag and drop files here, or click to select files</p>
              <p className="text-sm text-gray-500 mt-1">Supported files: .js, .jsx, .ts, .tsx, .py, etc.</p>
            </label>
          </div>
        </div>

        {/* SCAN FIRMWARE/BINARY */}
        <div className="bg-gray-800/50 p-4 rounded-lg mb-4">
          <h2 className="text-lg font-semibold text-gray-200 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 3v2m6-2v2m-3 0a3 3 0 0 0-3 3v2h6V5a3 3 0 0 0-3-3z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 9h2m10 0h2M5 15h2m10 0h2M7 9v6m10-6v6M5 12h14" />
            </svg>
            Scan Firmware/Binary <span className="text-xs text-yellow-400">(Coming Soon!)</span>
          </h2>
          <div className="border-2 border-dashed border-gray-600 rounded-lg p-4 text-center">
            <p className="text-gray-300">Drag and drop firmware files here, or click to select files</p>
            <p className="text-sm text-gray-500 mt-1">Supported files: .bin, .fw, .img, .hex</p>
          </div>
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
              Rate limit: {rateLimitInfo.remaining} requests remaining. Resets at{' '}
              {new Date(rateLimitInfo.reset * 1000).toLocaleTimeString()}
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
              includeFirmware={includeFirmware}
            />
            {firmwareMessage && (
              <Alert className="my-4" variant="default">
                <AlertDescription>{firmwareMessage}</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {/* GITHUB TOKEN NOTICE (if no token) */}
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

      {/* FOOTER */}
      <footer className="mt-8 border-t border-gray-700 pt-8 pb-4 bg-gray-900">
        <div className="max-w-4xl mx-auto space-y-4">
          <div className="bg-yellow-900/50 border border-yellow-600/50 rounded-lg p-4 mb-6 text-sm text-yellow-200">
            <p>
              <strong>Notice:</strong> SecurityLens is an educational tool. Please note:
            </p>
            <ul className="list-disc pl-5 mt-2 space-y-1">
              <li>This tool is designed for educational purposes only</li>
              <li>Detection patterns are currently bespoke to this project</li>
              <li>Integrating patterns from semgrep, walkbin, Ghirdra, etc. is on the todo list</li>
              <li>Contributions are greatly appreciated</li>
            </ul>
          </div>

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
                <tr className="border-b border-gray-700">
                  <td className="py-2 px-4">Dangerous Code Execution</td>
                  <td className="py-2 px-4">Dangerous code execution via <code>eval()</code></td>
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
              of this software and associated documentation files (the "Software"), ...
            </p>
            <p>
              THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
              IMPLIED...
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
}

export default ScannerUI;
