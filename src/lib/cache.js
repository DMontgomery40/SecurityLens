// Cache implementation for repository data
class RepositoryCache {
    constructor() {
        this.CACHE_KEY = 'repo_scan_cache';
        this.CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours
        this.initializeCache();
    }

    initializeCache() {
        try {
            const cached = localStorage.getItem(this.CACHE_KEY);
            this.cache = cached ? JSON.parse(cached) : {};
            
            // Clean up expired entries
            const now = Date.now();
            Object.keys(this.cache).forEach(key => {
                if (now > this.cache[key].expiry) {
                    delete this.cache[key];
                }
            });
            this.saveCache();
        } catch (error) {
            console.error('Error initializing cache:', error);
            this.cache = {};
        }
    }

    saveCache() {
        try {
            localStorage.setItem(this.CACHE_KEY, JSON.stringify(this.cache));
        } catch (error) {
            console.error('Error saving cache:', error);
            // If localStorage is full, clear old entries
            if (error.name === 'QuotaExceededError') {
                this.clearOldEntries();
                this.saveCache();
            }
        }
    }

    clearOldEntries() {
        const entries = Object.entries(this.cache);
        if (entries.length === 0) return;

        // Sort by expiry and remove oldest half
        entries.sort((a, b) => a[1].expiry - b[1].expiry);
        const halfLength = Math.floor(entries.length / 2);
        
        entries.slice(0, halfLength).forEach(([key]) => {
            delete this.cache[key];
        });
    }

    generateKey(url, token) {
        // Include part of token hash in key to differentiate between authenticated and non-authenticated requests
        const tokenHash = token ? this.hashCode(token).toString().slice(-8) : 'no-auth';
        return `${url}:${tokenHash}`;
    }

    hashCode(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash;
    }

    get(url, token) {
        const key = this.generateKey(url, token);
        const entry = this.cache[key];
        
        if (!entry) return null;
        if (Date.now() > entry.expiry) {
            delete this.cache[key];
            this.saveCache();
            return null;
        }
        
        return entry.data;
    }

    set(url, token, data) {
        const key = this.generateKey(url, token);
        this.cache[key] = {
            data,
            expiry: Date.now() + this.CACHE_DURATION
        };
        this.saveCache();
    }

    clear() {
        this.cache = {};
        this.saveCache();
    }
}

// For CLI environment where localStorage isn't available
const isNode = typeof window === 'undefined';
if (isNode) {
    global.localStorage = {
        _data: {},
        setItem: function(id, val) { return this._data[id] = String(val); },
        getItem: function(id) { return this._data.hasOwnProperty(id) ? this._data[id] : null; },
        removeItem: function(id) { return delete this._data[id]; },
        clear: function() { return this._data = {}; }
    };
}

export const repoCache = new RepositoryCache();