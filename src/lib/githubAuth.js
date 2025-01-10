// githubAuth.js

let localStorageAvailable = true;
try {
  localStorage.getItem('test');
} catch (e) {
  localStorageAvailable = false;
}

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
      console.warn('Unable to access localStorage:', error);
      return null;
    }
  }

  // etc...


  setToken(token) {
    try {
      if (token) {
        localStorage.setItem(this.tokenKey, token);
      } else {
        localStorage.removeItem(this.tokenKey);
      }
      this.token = token;
    } catch (error) {
      console.error('Failed to save token:', error);
      throw new Error('Unable to save GitHub token. Please check your browser settings.');
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