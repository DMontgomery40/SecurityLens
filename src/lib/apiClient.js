class ApiError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
        this.name = 'ApiError';
    }
}

import { authManager } from './githubAuth';

export async function scanRepository(url) {
    try {
        const token = authManager.getToken();
        if (!token) {
            throw new ApiError('GitHub token is required', 401);
        }

        const response = await fetch('/.netlify/functions/scan-repository', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            console.error('Scan failed with status:', response.status);
            const text = await response.text();
            console.error('Response body:', text);
            
            try {
                const errorData = JSON.parse(text);
                throw new ApiError(errorData.error || 'Scan failed', response.status);
            } catch (e) {
                throw new ApiError(
                    `Server error (${response.status}): ${text.slice(0, 100)}...`,
                    response.status
                );
            }
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Scan error details:', error);
        if (error instanceof ApiError) {
            throw error;
        }
        throw new ApiError('Scan failed: ' + error.message, 500);
    }
}
