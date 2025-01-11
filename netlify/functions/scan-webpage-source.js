// netlify/functions/scan-webpage-source.mjs
import axios from 'https://esm.sh/axios';
import * as cheerio from 'cheerio';
import VulnerabilityScanner from '../../src/lib/scanner.js';

// Utilities (if you need them):
// import validateToken from './utils/validate-token.js';
// import rateLimiter from './utils/rateLimiter.js';
// import secureToken from './utils/secureToken.js';

/**
 * Netlify serverless function to scan an arbitrary webpage URL.
 * 
 * Expects a JSON body: { "url": "https://example.com" }
 */

export const handler = async (event) => {
    // Add CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 204,
            headers
        };
    }

    try {
        const { url } = JSON.parse(event.body || '{}');
        if (!url) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'No URL provided' })
            };
        }

        console.log('Attempting to scan URL:', url);

        // Fetch the webpage
        let response;
        try {
            response = await axios.get(url);
        } catch (fetchError) {
            console.error('Error fetching URL:', fetchError.message);
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Failed to fetch URL',
                    details: fetchError.message 
                })
            };
        }

        const html = response.data;
        console.log('Successfully fetched HTML, parsing scripts...');

        // Parse HTML with Cheerio
        const $ = cheerio.load(html);
        const scripts = [];

        // Collect inline scripts and external script URLs
        $('script').each((i, elem) => {
            const src = $(elem).attr('src');
            if (src) {
                scripts.push({ type: 'external', src });
            } else {
                scripts.push({ type: 'inline', content: $(elem).html() });
            }
        });

        // Initialize scanner
        const scanner = new VulnerabilityScanner({});
        const scriptContents = [];

        // Process scripts
        for (const script of scripts) {
            if (script.type === 'inline') {
                scriptContents.push({ 
                    filename: 'inline-script', 
                    content: script.content 
                });
            } else {
                try {
                    const absoluteUrl = new URL(script.src, url).href;
                    const scriptResponse = await axios.get(absoluteUrl);
                    scriptContents.push({ 
                        filename: absoluteUrl, 
                        content: scriptResponse.data 
                    });
                } catch (err) {
                    console.error(`Failed to fetch script: ${script.src}`, err);
                }
            }
        }

        // Scan scripts
        const allFindings = [];
        for (const { filename, content } of scriptContents) {
            try {
                const fileFindings = await scanner.scanFile(content, filename, { 
                    scanType: 'web',
                    sourceContent: content
                });
                allFindings.push(...fileFindings);
            } catch (err) {
                console.error(`Error scanning script ${filename}`, err);
            }
        }

        // Generate report
        const report = scanner.generateReport(allFindings);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                message: 'Scan complete',
                scriptsScanned: scriptContents.length,
                report,
                findings: allFindings
            })
        };

    } catch (err) {
        console.error('Scan error:', err);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Internal server error',
                details: err.message,
                stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
            })
        };
    }
};
