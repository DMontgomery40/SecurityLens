import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState
} from 'react';
import VulnerabilityScanner, { scanRepositoryLocally } from '../lib/scanner';
import { authManager } from '../lib/githubAuth';
import { scanWebPage } from '../lib/apiClient.js';
import {
  getErrorMetadata,
  getUserFacingMessage,
  normalizeError
} from '../lib/errors.js';
import { createLogger, createRequestId, withLogContext } from '../lib/logger.js';

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
  const [error, setErrorState] = useState(null);
  const [errorMeta, setErrorMeta] = useState(null);
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
  const loggerRef = useRef(
    createLogger({
      component: 'ScanProvider',
      sessionId: createRequestId('session')
    })
  );

  const setError = useCallback((message, meta = null) => {
    setErrorState(message);
    setErrorMeta(message ? meta : null);
  }, []);

  const clearFeedback = useCallback(() => {
    setError(null);
    setSuccessMessage('');
  }, [setError]);

  const handleProgress = useCallback((progressData) => {
    setProgress(progressData);
  }, []);

  const handleUiError = useCallback((error, fallbackMessage, requestId) => {
    const normalized = normalizeError(error, {
      message: fallbackMessage,
      requestId,
      userMessage: error?.userMessage || fallbackMessage
    });

    setError(getUserFacingMessage(normalized, fallbackMessage), {
      code: normalized.code,
      requestId: normalized.requestId || requestId,
      status: normalized.status
    });

    return normalized;
  }, [setError]);

  // File Upload (Local) scanning
  const scanLocalFiles = useCallback(async (files) => {
    if (files.length === 0) return;

    const requestId = createRequestId('scan');
    const scanLogger = withLogContext(loggerRef.current, {
      action: 'scan-local-files',
      requestId
    });

    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    clearFeedback();
    setScanResults(null);
    setUsedCache(false);
    setRateLimitInfo(null);
    setProgress({
      phase: 'initializing',
      current: 0,
      total: files.length,
      details: {}
    });
    setFirmwareMessage('');

    scanLogger.info(
      {
        files: files.length,
        includeFirmware
      },
      'Starting local file scan'
    );

    try {
      const scanner = new VulnerabilityScanner({
        onProgress: handleProgress,
        logger: scanLogger,
        runId: requestId
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

      scanLogger.info(
        {
          findings: results.summary.totalIssues,
          partial: results.partial || false
        },
        'Local file scan completed'
      );
    } catch (error) {
      const normalized = handleUiError(error, 'Error scanning files', requestId);
      scanLogger.error(getErrorMetadata(normalized), 'Local file scan failed');
    } finally {
      setScanning(false);
    }
  }, [clearFeedback, handleProgress, handleUiError, includeFirmware]);

  // GitHub repo scanning
  const scanRepository = useCallback(async (urlInput) => {
    if (!urlInput) return;

    const requestId = createRequestId('scan');
    const scanLogger = withLogContext(loggerRef.current, {
      action: 'scan-repository',
      requestId
    });

    if (!authManager.hasToken()) {
      setError('GitHub token required for repository scanning', {
        code: 'MISSING_TOKEN',
        requestId,
        status: 401
      });
      return;
    }

    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    clearFeedback();
    setScanResults(null);
    setUsedCache(false);
    setFirmwareMessage('');
    setRateLimitInfo(null);
    setProgress({
      phase: 'fetching',
      current: 0,
      total: 0,
      details: { url: urlInput }
    });

    scanLogger.info(
      {
        url: urlInput,
        includeFirmware
      },
      'Starting repository scan'
    );

    try {
      const results = await scanRepositoryLocally(urlInput, handleProgress, {
        logger: scanLogger,
        requestId
      });

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

        const scanStatsMsg = results.scanStats 
          ? ` • Scanned ${results.scanStats.successCount}/${results.scanStats.totalFiles} files (${results.scanStats.completionRate}%) in ${results.scanStats.duration}s`
          : '';
        
        const partialMsg = results.partial ? ' • Some files failed to download' : '';
        
        setSuccessMessage(
          `Scan complete! Found ${results.summary.totalIssues} potential vulnerabilities ` +
          `(${results.summary.criticalIssues} critical, ` +
          `${results.summary.highIssues} high, ` +
          `${results.summary.mediumIssues} medium, ` +
          `${results.summary.lowIssues} low)${scanStatsMsg}${partialMsg}`
        );

        setUsedCache(results.fromCache || false);

        if (includeFirmware) {
          setFirmwareMessage('Firmware/Binary Analysis is coming soon!');
        }

        scanLogger.info(
          {
            findings: results.summary.totalIssues,
            fromCache: results.fromCache || false,
            partial: results.partial || false
          },
          'Repository scan completed'
        );
      } else {
        setSuccessMessage(`Found ${results.files.length} files in repository`);
      }

      if (results.rateLimit) {
        setRateLimitInfo(results.rateLimit);
      }
    } catch (error) {
      const normalized = handleUiError(
        error,
        error?.status === 403
          ? 'Rate limit exceeded. Please try again later.'
          : 'Repository scan failed',
        requestId
      );
      scanLogger.error(getErrorMetadata(normalized), 'Repository scan failed');
    } finally {
      setScanning(false);
    }
  }, [clearFeedback, handleProgress, handleUiError, includeFirmware, setError]);

  // Website scanning
  const scanWebsite = useCallback(async (url) => {
    const requestId = createRequestId('scan');
    const scanLogger = withLogContext(loggerRef.current, {
      action: 'scan-website',
      requestId
    });

    setScanning(true);
    progressRef.current?.scrollIntoView({ behavior: 'smooth' });
    clearFeedback();
    setScanResults(null);
    setRateLimitInfo(null);
    const startTime = Date.now();
    setProgress({
      phase: 'fetching',
      current: 0,
      total: 0,
      details: { 
        url,
        status: 'Fetching webpage content...',
        startTime
      }
    });
    setFirmwareMessage('');

    scanLogger.info(
      {
        url
      },
      'Starting website scan'
    );

    try {
      const urlPattern = /^(https?:\/\/)?([a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(:\d+)?(\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]*)?$/;
      if (!urlPattern.test(url)) {
        throw normalizeError(new Error('Please enter a valid website URL'), {
          code: 'INVALID_WEBSITE_URL',
          status: 400,
          requestId,
          userMessage: 'Please enter a valid website URL'
        });
      }

      const data = await scanWebPage(url, {
        requestId
      });
      const report = data.report || (
        data.findings && data.summary
          ? {
              findings: data.findings,
              summary: data.summary
            }
          : null
      );
      const rawFindings = Array.isArray(data.findings) ? data.findings : [];

      if (report?.findings && report.summary) {
        const mergedFindings = report.findings.map((finding) => {
          const rawFinding = rawFindings.find((candidate) => 
            candidate.type === finding.type && finding.files?.includes(candidate.file)
          );
          return {
            ...finding,
            codeLines: rawFinding?.codeLines || [],
            scanType: 'web'
          };
        });

        const finalReport = {
          ...report,
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

        const duration = Math.round((Date.now() - startTime) / 1000 * 100) / 100;
        const scriptCount = data.scriptsScanned || 0;
        const totalScanned = scriptCount + 1;
        
        setProgress({
          phase: 'completed',
          current: totalScanned,
          total: totalScanned,
          details: {
            duration,
            successCount: totalScanned,
            failureCount: 0,
            completionRate: 100,
            totalAttempted: totalScanned,
            summary: `Scanned ${totalScanned} items (HTML + ${scriptCount} scripts) in ${duration}s`
          }
        });

        setSuccessMessage(
          `Website scan complete! Found ${summary.totalIssues || 0} potential vulnerabilities • ` +
          `Scanned ${totalScanned} items in ${duration}s`
        );

        scanLogger.info(
          {
            findings: summary.totalIssues || 0,
            scannedItems: totalScanned,
            duration
          },
          'Website scan completed'
        );
      } else {
        const duration = Math.round((Date.now() - startTime) / 1000 * 100) / 100;
        
        setProgress({
          phase: 'completed',
          current: 1,
          total: 1,
          details: {
            duration,
            successCount: 1,
            failureCount: 0,
            completionRate: 100,
            totalAttempted: 1,
            summary: `Scanned webpage in ${duration}s`
          }
        });
        
        setSuccessMessage(`Website scan completed in ${duration}s, but no vulnerabilities reported.`);
      }
    } catch (error) {
      const normalized = handleUiError(
        error,
        'Error scanning website. Please check the URL and try again.',
        requestId
      );
      scanLogger.error(getErrorMetadata(normalized), 'Website scan failed');
    } finally {
      setScanning(false);
    }
  }, [clearFeedback, handleUiError]);

  const cancelScan = useCallback(() => {
    loggerRef.current.warn('Scan cancelled by user');
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
        (finding.files || []).some((file) =>
          file.toLowerCase().includes(searchQuery.toLowerCase())
        );

      const matchesSeverity =
        activeSeverity === 'ALL' || finding.severity === activeSeverity;

      return matchesSearch && matchesSeverity;
    });

    setFilteredByType(filtered);

    const byFile = filtered.reduce((acc, finding) => {
      (finding.files || []).forEach((file) => {
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
    errorMeta,
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
