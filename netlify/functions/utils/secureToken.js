import { SignJWT, jwtVerify } from 'jose';
import { createHash } from 'crypto';

const SECRET_KEY = process.env.JWT_SECRET_KEY;
if (!SECRET_KEY) {
  throw new Error('JWT_SECRET_KEY environment variable is required');
}

const encoder = new TextEncoder();

export async function encryptToken(githubToken) {
  const hashedToken = createHash('sha256').update(githubToken).digest('hex');
  
  const jwt = await new SignJWT({ token: hashedToken })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('2h')
    .setIssuedAt()
    .sign(encoder.encode(SECRET_KEY));

  return jwt;
}

export async function decryptToken(jwt) {
  try {
    const { payload } = await jwtVerify(jwt, encoder.encode(SECRET_KEY));
    return payload.token;
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
}

export async function validateGitHubToken(token) {
  try {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (!response.ok) {
      throw new Error('Invalid GitHub token');
    }

    return true;
  } catch (error) {
    throw new Error('Failed to validate GitHub token');
  }
}