// In-memory progress tracking (will be lost on function restart)
const scanProgress = new Map();

export class ProgressHandler {
  constructor(callback) {
    this.callback = callback;
    this.total = 0;
    this.current = 0;
    this.phase = 'initializing';
    this.details = {};
  }

  setTotal(total) {
    this.total = total;
    this.emitProgress();
  }

  increment() {
    this.current++;
    this.emitProgress();
  }

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

  complete() {
    this.phase = 'complete';
    this.current = this.total;
    this.emitProgress();
  }

  setPhase(phase, details = {}) {
    this.phase = phase;
    this.details = { ...this.details, ...details };
    this.emitProgress();
  }

  getProgressMessage() {
    switch (this.phase) {
      case 'fetching':
        return `Fetching files (${this.current}/${this.total})`;
      case 'analyzing':
        return `Analyzing ${this.details.currentFile || ''} (${this.current}/${this.total})`;
      case 'complete':
        return 'Scan complete';
      default:
        return `Scanning file ${this.current} of ${this.total}`;
    }
  }
}

export const updateProgress = (scanId, data) => {
  scanProgress.set(scanId, {
    ...data,
    timestamp: Date.now()
  });
};

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