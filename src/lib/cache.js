import Cache from './cache/Cache.js';

// Backward compatibility wrapper for the old RepositoryCache interface
class RepositoryCache {
  constructor() {
    this.cache = new Cache();
  }

  generateKey(url) {
    return `legacy:${url.toLowerCase()}`;
  }

  get(url) {
    const key = this.generateKey(url);
    return this.cache.get(key);
  }

  set(url, data) {
    // Don't cache error responses
    if (data && data.error) return;

    const key = this.generateKey(url);
    this.cache.set(key, data, 24 * 60 * 60); // 24 hours TTL
  }

  clear() {
    this.cache.clear();
  }
}

export const repoCache = new RepositoryCache();