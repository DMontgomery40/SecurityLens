import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, Globe, Folder } from 'lucide-react';
import VulnerabilityScanner from '../lib/scanner';
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
                setProgress(prev => ({ ...prev, current: i + 1 }));
                
                const content = await file.text();
                const findings = await scanner.scanFile(content, file.name);
                if (findings.length > 0) {
                    allFindings = [...allFindings, ...findings];
                }
            }

            if (allFindings.length === 0) {
                setSuccessMessage(`${files.length} file${files.length > 1 ? 's' : ''} scanned. No vulnerabilities found!`);
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
                setProgress(prev => ({ ...prev, current: i + 1 }));
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
        <div className="p-6 max-w-4xl mx-auto">
            <div className="mb-6">
                <h1 className="text-2xl font-bold">Plugin Vulnerability Scanner</h1>
                <p className="text-gray-600">Scan JavaScript files or repositories for security vulnerabilities</p>
            </div>

            <div className="space-y-4 mb-6">
                {/* URL Input */}
                <div className="flex gap-2">
                    <div className="flex-1">
                        <input
                            type="text"
                            value={urlInput}
                            onChange={(e) => setUrlInput(e.target.value)}
                            placeholder="Enter repository URL (e.g., https://github.com/user/repo/tree/main/src)"
                            className="w-full px-4 py-2 border rounded"
                        />
                    </div>
                    <button
                        onClick={handleUrlScan}
                        disabled={scanning || !urlInput}
                        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50 flex items-center gap-2"
                    >
                        <Globe className="h-4 w-4" />
                        Scan URL
                    </button>
                </div>

                {/* File Input */}
                <div className="flex items-center gap-2">
                    <input
                        type="file"
                        accept=".js,.ts,.jsx,.tsx"
                        onChange={handleFileSelect}
                        className="hidden"
                        id="fileInput"
                        multiple
                    />
                    <label
                        htmlFor="fileInput"
                        className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 cursor-pointer disabled:opacity-50 flex items-center gap-2"
                    >
                        <Folder className="h-4 w-4" />
                        Select Files
                    </label>
                </div>
            </div>

            {/* Progress Bar */}
            {scanning && progress.total > 0 && (
                <div className="mb-4">
                    <div className="h-2 bg-gray-200 rounded-full">
                        <div
                            className="h-2 bg-blue-500 rounded-full transition-all duration-300"
                            style={{ width: `${(progress.current / progress.total) * 100}%` }}
                        ></div>
                    </div>
                    <div className="text-sm text-gray-600 mt-1">
                        Scanning file {progress.current} of {progress.total}
                    </div>
                </div>
            )}

            {/* Success Message */}
            {successMessage && (
                <div className="mb-4 p-4 bg-green-100 text-green-700 rounded">
                    <div className="flex items-center">
                        <CheckCircle2 className="h-5 w-5 mr-2" />
                        <div>{successMessage}</div>
                    </div>
                </div>
            )}

            {/* Error Message */}
            {error && (
                <div className="mb-4 p-4 bg-red-100 text-red-700 rounded">
                    <div className="flex items-center">
                        <AlertTriangle className="h-5 w-5 mr-2" />
                        <div>
                            <div className="font-bold">Error</div>
                            <div>{error}</div>
                        </div>
                    </div>
                </div>
            )}

            <ScanResults results={scanResults} />
        </div>
    );
};

export default ScannerUI;
