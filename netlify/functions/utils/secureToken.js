/* eslint-env node */
import { SignJWT, jwtVerify } from 'jose';
import { createHash } from 'crypto';
import { SecurityLensError } from '../../../src/lib/errors.js';
import { fetchWithTimeout } from '../../../src/lib/http.js';

const encoder = new TextEncoder();

function getSecretKey() {
  const secretKey = globalThis.process?.env?.JWT_SECRET_KEY;

  if (!secretKey) {
    throw new SecurityLensError('JWT secret is not configured', {
      code: 'MISSING_JWT_SECRET',
      status: 500,
      userMessage: 'Token validation is temporarily unavailable.',
      expose: false
    });
  }

  return secretKey;
}

export async function encryptToken(githubToken) {
  const hashedToken = createHash('sha256').update(githubToken).digest('hex');
  
  const jwt = await new SignJWT({ token: hashedToken })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('2h')
    .setIssuedAt()
    .sign(encoder.encode(getSecretKey()));

  return jwt;
}

export async function decryptToken(jwt) {
  try {
    const { payload } = await jwtVerify(jwt, encoder.encode(getSecretKey()));
    return payload.token;
  } catch (error) {
    throw new SecurityLensError('Invalid or expired token', {
      code: 'INVALID_SECURE_TOKEN',
      status: 401,
      userMessage: 'Invalid or expired token',
      cause: error
    });
  }
}

export async function validateGitHubToken(token) {
  try {
    const response = await fetchWithTimeout('https://api.github.com/user', {
      timeoutMs: 8000,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3+json'
      }
    });

    if (!response.ok) {
      throw new SecurityLensError('Invalid GitHub token', {
        code: 'INVALID_GITHUB_TOKEN',
        status: 401,
        userMessage: 'Invalid GitHub token'
      });
    }

    return true;
  } catch (error) {
    if (error instanceof SecurityLensError) {
      throw error;
    }

    throw new SecurityLensError('Failed to validate GitHub token', {
      code: 'TOKEN_VALIDATION_FAILED',
      status: 502,
      userMessage: 'Failed to validate GitHub token',
      cause: error
    });
  }
}
