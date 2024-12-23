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