// In-memory progress tracking (will be lost on function restart)
const scanProgress = new Map();

export class ProgressHandler {
  constructor(callback) {
    this.callback = callback;
    this.total = 0;
    this.current = 0;
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
        type: 'progress',
        data: {
          current: this.current,
          total: this.total,
          percentage: this.total ? Math.round((this.current / this.total) * 100) : 0
        }
      });
    }
  }

  complete() {
    if (this.callback) {
      this.callback({
        type: 'complete',
        data: {
          current: this.current,
          total: this.total,
          percentage: 100
        }
      });
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