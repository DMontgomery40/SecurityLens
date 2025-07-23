// In-memory progress tracking (will be lost on function restart)
const scanProgress = new Map();

export class ProgressTracker {
  constructor(callback) {
    this.callback = callback;
    this.total = 0;
    this.current = 0;
    this.phase = 'initializing';
    this.details = {};
  }

  /**
   * Set the total number of items to process
   */
  setTotal(total) {
    this.total = total;
    this.emitProgress();
  }

  /**
   * Increment the current progress by 1
   */
  increment() {
    this.current++;
    this.emitProgress();
  }

  /**
   * Set the current progress value
   */
  setCurrent(current) {
    this.current = current;
    this.emitProgress();
  }

  /**
   * Emit progress update to callback
   */
  emitProgress() {
    if (this.callback) {
      this.callback({
        phase: this.phase,
        current: this.current,
        total: this.total,
        details: this.details,
        // Keep existing fields for backward compatibility
        status: this.phase,
        message: this.getProgressMessage()
      });
    }
  }

  /**
   * Mark progress as complete
   */
  complete() {
    this.phase = 'complete';
    this.current = this.total;
    this.emitProgress();
  }

  /**
   * Set the current phase and optional details
   */
  setPhase(phase, details = {}) {
    this.phase = phase;
    this.details = { ...this.details, ...details };
    this.emitProgress();
  }

  /**
   * Update progress with phase, current, total, and details
   */
  update(phase, current, total, details = {}) {
    if (phase !== undefined) {
      this.phase = phase;
    }
    if (current !== undefined) {
      this.current = current;
    }
    if (total !== undefined) {
      this.total = total;
    }
    if (Object.keys(details).length > 0) {
      this.details = { ...this.details, ...details };
    }
    this.emitProgress();
  }

  /**
   * Generate progress message based on current phase
   */
  getProgressMessage() {
    switch (this.phase) {
      case 'fetching':
        return `Fetching files (${this.current}/${this.total})`;
      case 'analyzing':
        return `Analyzing ${this.details.currentFile || ''} (${this.current}/${this.total})`;
      case 'complete':
        return 'Scan complete';
      case 'initializing':
        return 'Initializing scan...';
      default:
        return `Scanning file ${this.current} of ${this.total}`;
    }
  }

  /**
   * Reset progress to initial state
   */
  reset() {
    this.total = 0;
    this.current = 0;
    this.phase = 'initializing';
    this.details = {};
  }
}

/**
 * Update progress for a specific scan ID (for Netlify functions)
 */
export const updateProgress = (scanId, data) => {
  scanProgress.set(scanId, {
    ...data,
    timestamp: Date.now()
  });
};

/**
 * Get progress data for a specific scan ID
 */
export const getProgressForScan = async (scanId) => {
  const progress = scanProgress.get(scanId);
  
  if (!progress) {
    return {
      status: 'unknown',
      message: 'No progress data found for this scan'
    };
  }

  // Clear old progress data after 1 hour
  if (Date.now() - progress.timestamp > 3600000) {
    scanProgress.delete(scanId);
    return {
      status: 'expired',
      message: 'Scan progress data has expired'
    };
  }

  return {
    status: progress.status,
    current: progress.current,
    total: progress.total,
    message: progress.message
  };
};

// Alias for backward compatibility
export class ProgressHandler extends ProgressTracker {}