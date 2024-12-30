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

    // Validate files first
    const validFiles = files.filter(file => {
      // Check file size (max 10MB)
      if (file.size > 10 * 1024 * 1024) {
        setError(`File ${file.name} is too large (max 10MB)`);
        return false;
      }

      // Check file type - extensive list of file types that could contain vulnerabilities
      const validExtensions = [
        // Web/Frontend
        '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
        // Backend
        '.py', '.rb', '.php', '.java', '.jsp', '.asp', '.aspx', '.cs', '.go', '.rs', '.scala', '.kt', '.kts',
        // Configuration/Infrastructure
        '.xml', '.yaml', '.yml', '.json', '.toml', '.ini', '.conf', '.config', '.env', '.properties',
        '.dockerfile', 'dockerfile', '.docker-compose.yml', '.docker-compose.yaml',
        // Shell/Scripts
        '.sh', '.bash', '.zsh', '.bat', '.cmd', '.ps1', '.psm1',
        // Database
        '.sql', '.graphql', '.prisma',
        // Mobile
        '.swift', '.m', '.h', '.mm', '.kotlin', '.gradle',
        // Other
        '.pl', '.pm', '.t', '.perl', '.cgi',  // Perl
        '.lua',  // Lua
        '.r', '.rmd',  // R
        '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',  // C/C++
        '.ex', '.exs',  // Elixir
        '.erl', '.hrl',  // Erlang
        '.hs', '.lhs',  // Haskell
        '.ml', '.mli',  // OCaml
        '.fs', '.fsx', '.fsi',  // F#
        // Template files
        '.ejs', '.pug', '.jade', '.hbs', '.mustache', '.twig', '.liquid',
        // Build/Package files
        'package.json', 'package-lock.json', 'yarn.lock', 'pom.xml', 'build.gradle', 
        'requirements.txt', 'pipfile', 'gemfile', 'cargo.toml', 'mix.exs'
      ];
      
      const ext = file.name.toLowerCase();
      const isValidExtension = validExtensions.some(validExt => {
        if (validExt.startsWith('.')) {
          return ext.endsWith(validExt);
        }
        // For exact filename matches (like 'dockerfile')
        return ext === validExt;
      });

      if (!isValidExtension) {
        setError(`File type ${ext} is not supported`);
        return false;
      }

      return true;
    });

    if (validFiles.length === 0) {
      setError('No valid files to scan');
      return;
    }

    setScanning(true);
    setError(null);
    setProgress({ current: 0, total: validFiles.length });
    setScanResults(null);
    setUsedCache(false);
    
    try {
      const scanner = new VulnerabilityScanner({
        enableNewPatterns: true,
        enablePackageScanners: true,
        onProgress: (current, total) => {
          setProgress({ current, total });
        }
      });

      let allFindings = [];
      let processedFiles = 0;

      // Process files in batches to avoid memory issues
      const batchSize = 5;
      for (let i = 0; i < validFiles.length; i += batchSize) {
        const batch = validFiles.slice(i, i + batchSize);
        const batchPromises = batch.map(async (file) => {
          try {
            const content = await file.text();
            const fileFindings = await scanner.scanFile(content, file.name);
            return { file: file.name, findings: fileFindings };
          } catch (err) {
            console.error(`Error scanning file ${file.name}:`, err);
            return { file: file.name, error: err.message };
          }
        });

        const batchResults = await Promise.all(batchPromises);
        batchResults.forEach(result => {
          if (result.findings) {
            allFindings.push(...result.findings);
          }
          processedFiles++;
          setProgress({ current: processedFiles, total: validFiles.length });
        });
      }

      // Process findings to ensure proper structure
      const processedFindings = allFindings.reduce((acc, finding) => {
        const key = finding.type;
        if (!acc[key]) {
          acc[key] = {
            type: finding.type,
            severity: finding.severity || 'LOW',
            description: finding.description || 'No description provided',
            allLineNumbers: { [finding.file]: finding.lineNumbers || [] }
          };
        } else {
          // Merge line numbers if same type
          const file = finding.file;
          if (!acc[key].allLineNumbers[file]) {
            acc[key].allLineNumbers[file] = finding.lineNumbers || [];
          } else {
            const merged = new Set([...acc[key].allLineNumbers[file], ...finding.lineNumbers]);
            acc[key].allLineNumbers[file] = Array.from(merged).sort((a, b) => a - b);
          }
        }
        return acc;
      }, {});

      const report = scanner.generateReport(allFindings);
      setScanResults({
        findings: processedFindings,
        summary: report.summary || {}
      });
      
      const { criticalIssues = 0, highIssues = 0, mediumIssues = 0, lowIssues = 0 } = report.summary || {};
      setSuccessMessage(
        `Scan complete! Found ${Object.keys(processedFindings).length} potential vulnerabilities ` +
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
    <div className="p-8 bg-white min-h-screen">
      {/* Main Input Section */}
      <div className="max-w-3xl mx-auto mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4 flex items-center">
          <Shield className="h-8 w-8 mr-2" />
          SecurityLens
        </h1>
        <p className="text-gray-600 mb-6 max-w-2xl">
          Scans code for security vulnerabilities including code injection, authentication bypass, 
          SQL injection, XSS, buffer issues, sensitive data exposure, and more. Supports JavaScript, 
          TypeScript, Python, and other languages.
        </p>

        {/* URL Input Section */}
        <div className="bg-gray-50 p-6 rounded-lg shadow-sm mb-4">
          <h2 className="text-lg font-semibold text-gray-700 mb-4">Scan Repository</h2>
          <div className="flex gap-4">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter GitHub repository URL"
              className="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleUrlScan}
              disabled={scanning || !urlInput}
              className={`px-6 py-2 rounded-md text-white font-medium ${
                scanning || !urlInput
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-700'
              }`}
            >
              {scanning ? 'Scanning...' : 'Scan Repository'}
            </button>
          </div>
        </div>

        {/* File Upload Section */}
        <div className="bg-gray-50 p-6 rounded-lg shadow-sm">
          <h2 className="text-lg font-semibold text-gray-700 mb-4">Scan Local Files</h2>
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
              className="inline-flex flex-col items-center justify-center px-4 py-6 bg-gray-50 rounded-lg border-2 border-dashed border-gray-300 cursor-pointer hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <div className="mb-2">
                <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                    d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" 
                  />
                </svg>
              </div>
              <p className="text-gray-600">
                Drag and drop files here, or click to select files
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Supported files: .js, .jsx, .ts, .tsx, .py, and more
              </p>
            </label>
          </div>
        </div>

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
              {progress.current === progress.total 
                ? 'Processing results...' 
                : `Scanning file ${progress.current} of ${progress.total}`
              }
            </div>
          </div>
        )}

        {/* Success Message */}
        {successMessage && (
          <Alert className="mb-4" variant="default">
            <AlertDescription>{successMessage}</AlertDescription>
          </Alert>
        )}

        {/* Error Message */}
        {error && (
          <Alert className="mb-4" variant="error">
            <AlertDescription>
              <AlertTriangle className="h-4 w-4 inline-block mr-2" />
              {error}
            </AlertDescription>
          </Alert>
        )}

        {/* Rate Limit Info */}
        {rateLimitInfo && rateLimitInfo.remaining < 10 && (
          <Alert className="mb-4" variant="warning">
            <AlertDescription>
              Rate limit: {rateLimitInfo.remaining} requests remaining.
              Resets at {new Date(rateLimitInfo.reset * 1000).toLocaleTimeString()}
            </AlertDescription>
          </Alert>
        )}

        {/* Scan Results */}
        {scanResults && (
          <ScanResults 
            data={scanResults}
            usedCache={usedCache}
            onRefreshRequest={handleUrlScan}
            scanning={scanning}
          />
        )}

        {/* If user has no token, show a quick form to set one */}
        {!githubToken && (
          <div className="bg-gray-50 p-6 rounded-lg shadow-sm mb-4">
            <h2 className="text-lg font-semibold text-gray-700 mb-4">GitHub Access Token</h2>
            <p className="text-sm text-gray-600 mb-4">
              To scan repositories, you'll need a GitHub personal access token. 
              This stays in your browser and is never sent to any server.
            </p>
            <input 
              type="password"
              placeholder="GitHub token"
              onChange={(e) => handleTokenSubmit(e.target.value)}
              className="w-full px-4 py-2 border rounded"
            />
            <a 
              href="https://github.com/settings/tokens/new" 
              target="_blank"
              className="text-sm text-blue-600 hover:underline mt-2 inline-block"
            >
              Generate a token
            </a>
          </div>
        )}
      </div>

      {/* Token Dialog */}
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
                Go to <a 
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
              className="w-full px-4 py-2 border rounded"
              onChange={(e) => handleTokenSubmit(e.target.value)}
            />
          </div>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default ScannerUI;
