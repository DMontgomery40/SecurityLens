// githubAuth.js
import { createLogger } from './logger.js';

let localStorageAvailable = true;
try {
  localStorage.getItem('test');
} catch {
  localStorageAvailable = false;
}

const logger = createLogger({
  component: 'GitHubAuthManager'
});

export class GitHubAuthManager {
  constructor() {
    this.tokenKey = 'security_lens_gh_token';
    this.token = localStorageAvailable ? this.loadToken() : null;
  }

  loadToken() {
    // if localStorageAvailable is false, skip
    if (!localStorageAvailable) return null;

    try {
      return localStorage.getItem(this.tokenKey);
    } catch (error) {
      logger.warn(
        {
          err: error
        },
        'Unable to access localStorage while loading token'
      );
      return null;
    }
  }

  // etc...


  setToken(token) {
    try {
      if (localStorageAvailable) {
        if (token) {
          localStorage.setItem(this.tokenKey, token);
        } else {
          localStorage.removeItem(this.tokenKey);
        }
      }
      this.token = token;
    } catch (error) {
      logger.error(
        {
          err: error
        },
        'Failed to persist GitHub token'
      );
      if (localStorageAvailable) {
        throw new Error('Unable to save GitHub token. Please check your browser settings.');
      }
      // In Node.js environment, just set the token in memory
    }
  }

  hasToken() {
    return !!this.token;
  }

  getToken() {
    return this.token;
  }

  clearToken() {
    this.setToken(null);
  }

  // Validate token format (basic check)
  isValidTokenFormat(token) {
    return /^(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})$/.test(token);
  }

  // etc...

}

export const authManager = new GitHubAuthManager();
