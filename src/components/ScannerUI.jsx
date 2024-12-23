import React, { useState, useCallback } from 'react';
import { 
  AlertTriangle, 
  Shield 
} from 'lucide-react';
import { scanRepository } from '../lib/apiClient';
import { Alert, AlertDescription } from './ui/alert';
import VulnerabilityScanner from '../lib/scanner';

const ScannerUI = () => {
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [urlInput, setUrlInput] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [scanResults, setScanResults] = useState(null);

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setScanning(true);
    setError(null);
    setProgress({ current: 0, total: files.length });
    setScanResults(null);
    
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

      const results = scanner.generateReport(allFindings);
      setScanResults(results);
      setSuccessMessage(`Scan complete! Found ${allFindings.length} potential vulnerabilities.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleUrlScan = useCallback(async () => {
    if (!urlInput) return;
    
    setScanning(true);
    setError(null);
    setScanResults(null);
    
    try {
      const results = await scanRepository(urlInput);
      console.log('Scan results:', results);
      
      if (results.findings && results.summary) {
        setScanResults({
          findings: results.findings,
          summary: results.summary
        });
        setSuccessMessage(
          `Scan complete! Found ${results.summary.totalIssues} potential vulnerabilities ` +
          `(${results.summary.criticalIssues} critical, ${results.summary.highIssues} high, ` +
          `${results.summary.mediumIssues} medium, ${results.summary.lowIssues} low)`
        );
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

  return (
    <div className="p-8 bg-gray-100 min-h-screen">
      {/* Main Input Section */}
      <div className="max-w-3xl mx-auto mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4 flex items-center">
          <Shield className="h-8 w-8 mr-2" />
          Plugin Vulnerability Scanner
        </h1>

        {/* URL Input Section */}
        <div className="bg-white p-6 rounded-lg shadow-sm mb-4">
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
        <div className="bg-white p-6 rounded-lg shadow-sm mb-4">
          <h2 className="text-lg font-semibold text-gray-700 mb-4">Upload Files</h2>
          <div className="flex flex-col gap-4">
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
              <input
                type="file"
                onChange={handleFileUpload}
                multiple
                className="hidden"
                id="file-upload"
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center justify-center"
              >
                <div className="mb-2">
                  <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
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
              {progress.current === progress.total ? 
                'Processing results...' : 
                `Scanning file ${progress.current} of ${progress.total}`
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
          <div className="bg-white p-6 rounded-lg shadow-sm">
            <h2 className="text-lg font-semibold text-gray-700 mb-4">Scan Results</h2>
            <pre className="bg-gray-100 p-4 rounded-lg overflow-auto">
              {JSON.stringify(scanResults, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScannerUI;