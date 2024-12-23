class ApiError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
        this.name = 'ApiError';
    }
}

export async function scanRepository(url) {
    try {
        const response = await fetch('/.netlify/functions/scan-repository', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
            throw new ApiError(
                'Server error: The scanning service is not available. This typically means the app needs to be deployed to Netlify to work properly.',
                503
            );
        }

        const data = await response.json();

        if (!response.ok) {
            throw new ApiError(data.error || 'Scan failed', response.status);
        }

        return data;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        if (error.name === 'SyntaxError') {
            throw new ApiError(
                'Server error: Received invalid response. The scanning service may not be properly configured.',
                500
            );
        }
        throw new ApiError('Scan failed: ' + error.message, 500);
    }
}