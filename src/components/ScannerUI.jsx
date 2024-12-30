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
      <div className="flex flex-col gap-8 p-8">
        <div className="flex flex-col gap-4">
          {/* File Upload Section */}
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
            <input
              type="file"
              multiple
              onChange={handleFileUpload}
              className="hidden"
              id="file-upload"
            />
            <label
              htmlFor="file-upload"
              className="cursor-pointer text-gray-600"
            >
              Drag and drop files here, or click to select files
              <div className="text-sm text-gray-500 mt-2">
                Supported files: js, jsx, ts, tsx, py, java, and more
              </div>
            </label>
          </div>

          {/* Progress and Status */}
          {scanning && (
            <div className="text-center">
              <div className="animate-pulse text-blue-600">
                Scanning... {progress.current} of {progress.total} files
              </div>
            </div>
          )}

          {error && (
            <div className="text-red-600 text-center">
              {error}
            </div>
          )}

          {successMessage && (
            <div className="text-green-600 text-center">
              {successMessage}
            </div>
          )}
        </div>

        {/* Scan Results */}
        {scanResults && !scanning && (
          <ScanResults
            scanResults={scanResults}
            onRefreshRequest={() => {
              setScanResults(null);
              setSuccessMessage('');
            }}
          />
        )}
      </div>
    </div>
  );
};

export default ScannerUI;
