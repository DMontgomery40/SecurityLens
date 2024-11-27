import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import VulnerabilityScanner from '../lib/scanner';
import ScanButton from './ScanButton';
import ScanResults from './ScanResults';

const ScannerUI = () => {
  const [scanResults, setScanResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [urlInput, setUrlInput] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const handleFileSelect = async (event) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setProgress({ current: 0, total: files.length });

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

    try {
      const scanner = new VulnerabilityScanner();
      const files = await scanner.fetchRepositoryFiles(urlInput);
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
        setSuccessMessage(`Repository scanned. No vulnerabilities found!`);
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

      {/* Scan Buttons */}
      <ScanButton
        urlInput={urlInput}
        setUrlInput={setUrlInput}
        handleUrlScan={handleUrlScan}
        handleFileSelect={handleFileSelect}
        scanning={scanning}
      />

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
      <ScanResults results={scanResults} />
    </div>
  );
};

export default ScannerUI;
