class ApiError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
        this.name = 'ApiError';
    }
}

export async function validateGitHubToken(token) {
    try {
        const response = await fetch('/.netlify/functions/validate-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new ApiError(data.error || 'Token validation failed', response.status);
        }

        return data;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        throw new ApiError('Network error occurred', 500);
    }
}

export async function scanRepository(url, secureToken = null) {
    try {
        const response = await fetch('/.netlify/functions/scan-repository', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url,
                secureToken
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new ApiError(data.error || 'Scan failed', response.status);
        }

        return data;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        throw new ApiError('Network error occurred', 500);
    }
}