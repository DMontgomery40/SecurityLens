class Cache {
  constructor() {
    this.isNode = typeof window === 'undefined';
    this.cache = {};
    this.cacheFile = null;
    this.fs = null;
    this.path = null;
    this.os = null;
    
    if (this.isNode) {
      this.initializeNodeModules();
    } else {
      this.initializeBrowserCache();
    }
  }

  initializeNodeModules() {
    try {
      // Use require() for Node.js modules to avoid bundling issues
      this.fs = require('fs');
      this.path = require('path');
      this.os = require('os');
      this.initializeFileCache();
    } catch (error) {
      console.warn('Node.js modules not available, using in-memory cache only');
    }
  }

  initializeFileCache() {
    if (!this.fs || !this.path || !this.os) {
      console.warn('Node.js modules not loaded, using in-memory cache only');
      return;
    }

    const cacheDir = this.path.join(process.cwd(), '.cache');
    const tempCacheDir = this.path.join(this.os.tmpdir(), 'securitylens');
    
    try {
      if (!this.fs.existsSync(cacheDir)) {
        this.fs.mkdirSync(cacheDir, { recursive: true });
      }
      this.cacheFile = this.path.join(cacheDir, 'securitylens.json');
    } catch (error) {
      try {
        if (!this.fs.existsSync(tempCacheDir)) {
          this.fs.mkdirSync(tempCacheDir, { recursive: true });
        }
        this.cacheFile = this.path.join(tempCacheDir, 'securitylens.json');
      } catch (tempError) {
        console.warn('Unable to create cache directory, using in-memory cache only');
        this.cacheFile = null;
      }
    }
    
    this.loadFileCache();
  }

  initializeBrowserCache() {
    try {
      localStorage.getItem('test');
      this.localStorageAvailable = true;
      this.loadBrowserCache();
    } catch (e) {
      this.localStorageAvailable = false;
      console.warn('localStorage not available, using in-memory cache only');
    }
  }

  loadFileCache() {
    if (!this.cacheFile || !this.fs) return;
    
    try {
      if (this.fs.existsSync(this.cacheFile)) {
        const data = this.fs.readFileSync(this.cacheFile, 'utf8');
        this.cache = JSON.parse(data);
        this.clearExpired();
      }
    } catch (error) {
      console.warn('Error loading cache file, starting with empty cache:', error.message);
      this.cache = {};
    }
  }

  loadBrowserCache() {
    if (!this.localStorageAvailable) return;
    
    try {
      const cached = localStorage.getItem('securitylens_cache');
      this.cache = cached ? JSON.parse(cached) : {};
      this.clearExpired();
    } catch (error) {
      console.warn('Error loading localStorage cache, starting with empty cache:', error.message);
      this.cache = {};
    }
  }

  saveCache() {
    if (this.isNode && this.cacheFile) {
      this.saveFileCache();
    } else if (this.localStorageAvailable) {
      this.saveBrowserCache();
    }
  }

  saveFileCache() {
    if (!this.cacheFile || !this.fs) return;
    
    try {
      const tempFile = this.cacheFile + '.tmp';
      this.fs.writeFileSync(tempFile, JSON.stringify(this.cache, null, 2));
      this.fs.renameSync(tempFile, this.cacheFile);
    } catch (error) {
      console.warn('Error saving cache file:', error.message);
    }
  }

  saveBrowserCache() {
    try {
      localStorage.setItem('securitylens_cache', JSON.stringify(this.cache));
    } catch (error) {
      console.warn('Error saving localStorage cache:', error.message);
      if (error.name === 'QuotaExceededError') {
        this.clearExpired();
        try {
          localStorage.setItem('securitylens_cache', JSON.stringify(this.cache));
        } catch (retryError) {
          console.warn('Cache quota exceeded even after cleanup');
        }
      }
    }
  }

  get(key) {
    const entry = this.cache[key];
    
    if (!entry) {
      return null;
    }

    if (this.isExpired(entry)) {
      delete this.cache[key];
      this.saveCache();
      return null;
    }
    
    entry.lastAccessed = Date.now();
    this.saveCache();
    
    return entry.value;
  }

  set(key, value, ttlSeconds = 24 * 60 * 60) {
    if (this.shouldNotCache(value)) {
      return;
    }

    this.cache[key] = {
      value,
      expiry: Date.now() + (ttlSeconds * 1000),
      lastAccessed: Date.now(),
      created: Date.now()
    };
    
    this.saveCache();
  }

  clearExpired() {
    const now = Date.now();
    let hasExpired = false;
    
    Object.keys(this.cache).forEach(key => {
      if (this.isExpired(this.cache[key])) {
        delete this.cache[key];
        hasExpired = true;
      }
    });
    
    if (hasExpired) {
      this.saveCache();
    }
  }

  isExpired(entry) {
    return Date.now() > entry.expiry;
  }

  shouldNotCache(value) {
    if (typeof value === 'object' && value !== null) {
      const jsonString = JSON.stringify(value).toLowerCase();
      const sensitivePatterns = [
        'token',
        'password',
        'secret',
        'key',
        'authorization',
        'bearer',
        'auth'
      ];
      
      return sensitivePatterns.some(pattern => jsonString.includes(pattern));
    }
    
    if (typeof value === 'string') {
      const lowerValue = value.toLowerCase();
      if (lowerValue.includes('token') || 
          lowerValue.includes('password') || 
          lowerValue.includes('secret') ||
          lowerValue.startsWith('ghp_') ||
          lowerValue.startsWith('github_pat_')) {
        return true;
      }
    }
    
    return false;
  }

  clear() {
    this.cache = {};
    this.saveCache();
  }

  size() {
    return Object.keys(this.cache).length;
  }

  stats() {
    const entries = Object.values(this.cache);
    const now = Date.now();
    
    return {
      total: entries.length,
      expired: entries.filter(entry => this.isExpired(entry)).length,
      size: this.isNode && this.cacheFile ? this.getFileCacheSize() : this.getBrowserCacheSize()
    };
  }

  getFileCacheSize() {
    if (!this.cacheFile || !this.fs) return 0;
    
    try {
      if (this.fs.existsSync(this.cacheFile)) {
        return this.fs.statSync(this.cacheFile).size;
      }
    } catch (error) {
      console.warn('Error getting cache file size:', error.message);
    }
    return 0;
  }

  getBrowserCacheSize() {
    try {
      const cached = localStorage.getItem('securitylens_cache');
      return cached ? new Blob([cached]).size : 0;
    } catch (error) {
      return 0;
    }
  }
}

export default Cache;