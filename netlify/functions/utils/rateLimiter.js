/* eslint-env node */
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { SecurityLensError } from '../../../src/lib/errors.js';

const rateLimiter = new RateLimiterMemory({
  points: 30, // Number of points
  duration: 60, // Per minute
});

export async function checkRateLimit(ip) {
  try {
    await rateLimiter.consume(ip);
    return true;
  } catch {
    throw new SecurityLensError('Rate limit exceeded. Please try again later.', {
      code: 'RATE_LIMITED',
      status: 429,
      userMessage: 'Rate limit exceeded. Please try again later.'
    });
  }
}

// Separate rate limiter for token validation to prevent brute force
const tokenRateLimiter = new RateLimiterMemory({
  points: 5, // Number of attempts
  duration: 60, // Per minute
});

export async function checkTokenRateLimit(ip) {
  try {
    await tokenRateLimiter.consume(ip);
    return true;
  } catch {
    throw new SecurityLensError('Too many token validation attempts. Please try again later.', {
      code: 'TOKEN_RATE_LIMITED',
      status: 429,
      userMessage: 'Too many token validation attempts. Please try again later.'
    });
  }
}
