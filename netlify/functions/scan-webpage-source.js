// netlify/functions/scan-webpage-source.mjs
import axios from 'axios';
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
    // 1. Check HTTP method
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method Not Allowed' }),
        };
    }

    try {
        // 2. Parse incoming body
        const { url } = JSON.parse(event.body || '{}');
        if (!url) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'No URL provided' }),
            };
        }

        // (Optional) Validate token, rate-limit, etc.
        // const isValid = validateToken(event.headers.authorization);
        // if (!isValid) return { statusCode: 401, body: JSON.stringify({ error: 'Invalid token' }) };
        // await rateLimiter('scanWebpage', /* some user/ip identifier */);

        // 3. Fetch the webpage HTML
        const response = await axios.get(url, {
            // A user-agent helps avoid some sites blocking default requests
            headers: { 'User-Agent': 'SecurityLens/1.0' },
        });
        const html = response.data;

        // 4. Parse HTML with Cheerio to extract script tags
        const $ = cheerio.load(html);

        // Collect inline scripts and external script URLs
        const scripts = [];
        $('script').each((i, elem) => {
            const srcAttr = $(elem).attr('src');
            if (srcAttr) {
                // External script
                scripts.push({ type: 'external', src: srcAttr });
            } else {
                // Inline script
                scripts.push({ type: 'inline', content: $(elem).html() });
            }
        });

        // 5. Filter out known frameworks or unwanted scripts (basic example)
        // Adjust this logic as you see fit:
        const filteredScripts = scripts.filter(script => {
            // If inline, exclude if it clearly has 'React' or other frameworks
            if (script.type === 'inline') {
                const lower = script.content?.toLowerCase() || '';
                if (lower.includes('react') || lower.includes('vue') || lower.includes('angular')) {
                    return false;
                }
            }
            // If external, you might skip known CDNs or extension domains, e.g. 'chrome-extension://'
            if (script.type === 'external') {
                if (script.src.startsWith('chrome-extension://')) {
                    return false;
                }
                // Or skip if from a known CDN, e.g. 'cdn.jsdelivr.net'
            }
            return true;
        });

        // 6. Fetch external scripts + prepare final code to pass to the scanner
        const scriptContents = [];
        for (const script of filteredScripts) {
            if (script.type === 'inline') {
                scriptContents.push({ filename: 'inline-script', content: script.content });
            } else {
                // external script -> fetch content
                try {
                    // Convert relative paths to absolute if needed
                    const absoluteUrl = new URL(script.src, url).href;
                    const externalResp = await axios.get(absoluteUrl);
                    scriptContents.push({ filename: absoluteUrl, content: externalResp.data });
                } catch (err) {
                    // If fail to fetch, skip or log an error
                    console.error(`Failed fetching script at ${script.src}:`, err.message);
                }
            }
        }

        // 7. Use your VulnerabilityScanner to scan each script’s content
        const scanner = new VulnerabilityScanner({});
        const allFindings = [];
        for (const { filename, content } of scriptContents) {
            try {
                const fileFindings = await scanner.scanFile(content, filename);
                allFindings.push(...fileFindings);
            } catch (err) {
                console.error(`Error scanning script ${filename}`, err.message);
            }
        }

        // 8. Build a final report (assuming your scanner has generateReport, etc.)
        const report = scanner.generateReport(allFindings);

        // Return successful response
        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Scan complete',
                scriptsScanned: scriptContents.length,
                report,
            }),
        };
    } catch (err) {
        console.error('Scan error:', err);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Internal server error' }),
        };
    }
}
