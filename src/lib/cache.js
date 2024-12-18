class RepositoryCache {
    constructor() {
        this.CACHE_KEY = 'repo_scan_cache';
        this.CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours
        this.MAX_SIZE = 50 * 1024 * 1024; // 50MB max cache size
        this.initializeCache();
    }

    initializeCache() {
        try {
            const cached = localStorage.getItem(this.CACHE_KEY);
            this.cache = cached ? JSON.parse(cached) : {};
            
            // Clean up expired entries and check size
            this.cleanup();
        } catch (error) {
            console.error('Error initializing cache:', error);
            this.cache = {};
        }
    }

    cleanup() {
        const now = Date.now();
        let totalSize = 0;
        const entries = Object.entries(this.cache);
        
        // Sort by last accessed time
        entries.sort(([, a], [, b]) => b.lastAccessed - a.lastAccessed);
        
        for (const [key, entry] of entries) {
            // Remove expired entries
            if (now > entry.expiry) {
                delete this.cache[key];
                continue;
            }

            // Calculate size (approximate)
            const size = new TextEncoder().encode(JSON.stringify(entry)).length;
            totalSize += size;

            // If we exceed max size, remove oldest entries
            if (totalSize > this.MAX_SIZE) {
                delete this.cache[key];
            }
        }

        this.saveCache();
    }

    saveCache() {
        try {
            localStorage.setItem(this.CACHE_KEY, JSON.stringify(this.cache));
        } catch (error) {
            console.error('Error saving cache:', error);
            if (error.name === 'QuotaExceededError') {
                this.cleanup();
            }
        }
    }

    generateKey(url) {
        return url.toLowerCase();
    }

    get(url) {
        const key = this.generateKey(url);
        const entry = this.cache[key];
        
        if (!entry) return null;

        // Check expiration
        if (Date.now() > entry.expiry) {
            delete this.cache[key];
            this.saveCache();
            return null;
        }
        
        // Update last accessed time
        entry.lastAccessed = Date.now();
        this.saveCache();
        
        return entry.data;
    }

    set(url, data) {
        const key = this.generateKey(url);
        
        // Don't cache error responses
        if (data.error) return;

        this.cache[key] = {
            data,
            expiry: Date.now() + this.CACHE_DURATION,
            lastAccessed: Date.now()
        };

        this.cleanup();
    }

    clear() {
        this.cache = {};
        this.saveCache();
    }
}

export const repoCache = new RepositoryCache();