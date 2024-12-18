import { RateLimiterMemory } from 'rate-limiter-flexible';

const rateLimiter = new RateLimiterMemory({
  points: 30, // Number of points
  duration: 60, // Per minute
});

export async function checkRateLimit(ip) {
  try {
    await rateLimiter.consume(ip);
    return true;
  } catch (error) {
    throw new Error('Rate limit exceeded. Please try again later.');
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
  } catch (error) {
    throw new Error('Too many token validation attempts. Please try again later.');
  }
}