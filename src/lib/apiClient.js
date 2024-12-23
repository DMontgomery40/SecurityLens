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

        if (!response.ok) {
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('text/html')) {
                throw new ApiError(
                    'Server error: The scanning service is not available. Please ensure Netlify functions are properly configured.',
                    503
                );
            }

            const data = await response.json();
            throw new ApiError(data.error || 'Scan failed', response.status);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        if (error.name === 'SyntaxError') {
            throw new ApiError(
                'Server error: Invalid response from scanning service. Please check Netlify function logs.',
                500
            );
        }
        throw new ApiError('Scan failed: ' + error.message, 500);
    }
}