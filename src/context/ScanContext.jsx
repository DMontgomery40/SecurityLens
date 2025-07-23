import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import VulnerabilityScanner, { scanRepositoryLocally } from '../lib/scanner';
import { authManager } from '../lib/githubAuth';
import { scanWebPage } from '../lib/apiClient.js';

const ScanContext = createContext();

export const useScanContext = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
};

export const ScanProvider = ({ children }) => {
  // Scanning state
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({
    phase: 'initializing',
    current: 0,
    total: 0,
    details: {}
  });
  const [scanResults, setScanResults] = useState(null);
  const [usedCache, setUsedCache] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [severityStats, setSeverityStats] = useState({
    CRITICAL: { uniqueCount: 0, instanceCount: 0 },
    HIGH: { uniqueCount: 0, instanceCount: 0 },
    MEDIUM: { uniqueCount: 0, instanceCount: 0 },
    LOW: { uniqueCount: 0, instanceCount: 0 }
  });

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSeverity, setActiveSeverity] = useState('ALL');
  const [viewMode, setViewMode] = useState('type');
  const [filteredByType, setFilteredByType] = useState([]);
  const [filteredByFile, setFilteredByFile] = useState([]);

  // Firmware state
  const [includeFirmware, setIncludeFirmware] = useState(false);
  const [firmwareMessage, setFirmwareMessage] = useState('');

  // Refs
  const progressRef = useRef(null);
  const scanResultsRef = useRef(null);

  const handleProgress = (progressData) => {
    setProgress(progressData);
  };

  // File Upload (Local) scanning
  const scanLocalFiles = useCallback(async (files) => {
    if (files.length === 0) return;

    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    setError(null);
    setScanResults(null);
    setProgress({
      phase: 'initializing',
      current: 0,
      total: files.length,
      details: {}
    });
    setFirmwareMessage('');

    try {
      const scanner = new VulnerabilityScanner({
        onProgress: handleProgress
      });

      const results = await scanner.scanLocalFiles(files);
      setScanResults(results);
      scanResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });

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

      if (includeFirmware) {
        setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'Error scanning files');
    } finally {
      setScanning(false);
    }
  }, [includeFirmware]);

  // GitHub repo scanning
  const scanRepository = useCallback(async (urlInput) => {
    if (!urlInput) return;

    if (!authManager.hasToken()) {
      setError('GitHub token required for repository scanning');
      return;
    }

    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    setError(null);
    setScanResults(null);
    setUsedCache(false);
    setFirmwareMessage('');
    setProgress({
      phase: 'fetching',
      current: 0,
      total: 0,
      details: { url: urlInput }
    });

    try {
      const results = await scanRepositoryLocally(urlInput);
      console.log('Scan results:', results);

      if (results.findings && results.summary) {
        const normalizedResults = {
          findings: results.findings,
          summary: results.summary,
          rateLimit: results.rateLimit,
          fromCache: results.fromCache
        };
        
        setScanResults(normalizedResults);
        scanResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
  }, [includeFirmware]);

  // Website scanning
  const scanWebsite = useCallback(async (url) => {
    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setProgress({
      phase: 'fetching',
      current: 0,
      total: 0,
      details: { url }
    });
    setFirmwareMessage('');

    try {
      const urlPattern = /^(https?:\/\/)?([a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(:\d+)?(\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]*)?$/;
      if (!urlPattern.test(url)) {
        throw new Error('Please enter a valid website URL');
      }

      const data = await scanWebPage(url);

      if (data.findings && data.report) {
        const mergedFindings = data.report.findings.map(finding => {
          const rawFinding = data.findings.find(f => 
            f.type === finding.type && f.file === finding.files[0]
          );
          return {
            ...finding,
            codeLines: rawFinding?.codeLines || [],
            scanType: 'web'
          };
        });

        const finalReport = {
          ...data.report,
          findings: mergedFindings
        };

        setScanResults(finalReport);
        scanResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });

        const { summary } = finalReport;
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
  }, []);

  const cancelScan = useCallback(() => {
    setScanning(false);
    setProgress({
      phase: 'cancelled',
      current: 0,
      total: 0,
      details: {}
    });
  }, []);

  // Filter results by search & severity
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

  const value = {
    // State
    scanning,
    error,
    progress,
    scanResults,
    usedCache,
    successMessage,
    rateLimitInfo,
    selectedVulnerability,
    severityStats,
    searchQuery,
    activeSeverity,
    viewMode,
    filteredByType,
    filteredByFile,
    includeFirmware,
    firmwareMessage,
    progressRef,
    scanResultsRef,

    // Actions
    setError,
    setSuccessMessage,
    setSelectedVulnerability,
    setSearchQuery,
    setActiveSeverity,
    setViewMode,
    setIncludeFirmware,
    scanLocalFiles,
    scanRepository,
    scanWebsite,
    cancelScan
  };

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
};

export default ScanContext;