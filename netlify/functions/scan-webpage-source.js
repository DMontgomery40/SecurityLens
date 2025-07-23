import axios from 'axios';
import * as cheerio from 'cheerio';
import { FileScanner } from '../../src/lib/FileScanner.js';
import { ReportBuilder } from '../../src/lib/ReportBuilder.js';
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

        // Initialize modular components
        const fileScanner = new FileScanner({
            enableNewPatterns: true,
            enablePackageScanners: true
        });
        const reportBuilder = new ReportBuilder();
        const scriptContents = [];

        // Add the HTML content itself to be scanned
        scriptContents.push({
            filename: 'page.html',
            content: html
        });

        // Set up timeout for webpage scanning (25 seconds to stay under Netlify limit)
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Webpage scan timeout - too many scripts or large content')), 25000);
        });
        
        const scanPromise = (async () => {
            // Process scripts with concurrency control
            const maxConcurrentScripts = parseInt(process.env.WEBPAGE_SCRIPT_CONCURRENCY) || 5;
            let processedScripts = 0;
            
            for (let i = 0; i < scripts.length; i += maxConcurrentScripts) {
                const batch = scripts.slice(i, i + maxConcurrentScripts);
                const batchPromises = batch.map(async (script) => {
                    if (script.type === 'inline') {
                        return { 
                            filename: `inline-script-${processedScripts++}`, 
                            content: script.content || ''
                        };
                    } else {
                        try {
                            const absoluteUrl = new URL(script.src, url).href;
                            const scriptResponse = await axios.get(absoluteUrl, {
                                timeout: 5000, // 5 second timeout per script
                                maxContentLength: 1024 * 1024 // 1MB limit per script
                            });
                            return { 
                                filename: absoluteUrl, 
                                content: scriptResponse.data 
                            };
                        } catch (err) {
                            console.error(`Failed to fetch script: ${script.src}`, err.message);
                            return null;
                        }
                    }
                });
                
                const batchResults = await Promise.all(batchPromises);
                scriptContents.push(...batchResults.filter(result => result !== null));
            }
            
            console.log(`Retrieved ${scriptContents.length} scripts/content for scanning`);
            
            // Scan scripts using FileScanner
            const allFindings = [];
            let scannedCount = 0;
            
            for (const { filename, content } of scriptContents) {
                try {
                    if (content && typeof content === 'string' && content.trim()) {
                        const fileFindings = await fileScanner.scanFile(content, filename, { 
                            scanType: 'web',
                            sourceContent: content
                        });
                        if (fileFindings && fileFindings.length > 0) {
                            allFindings.push(...fileFindings);
                        }
                        scannedCount++;
                    }
                } catch (err) {
                    console.error(`Error scanning content ${filename}:`, err.message);
                }
            }
            
            console.log(`Scan complete: ${allFindings.length} findings from ${scannedCount} scanned items`);
            return { allFindings, scannedCount };
        })();
        
        // Race between scan and timeout
        const { allFindings, scannedCount } = await Promise.race([scanPromise, timeoutPromise]);
        
        // Generate report using ReportBuilder
        const report = reportBuilder.generateReport(allFindings, { 
            scanType: 'webpage',
            sourceUrl: url,
            scriptsScanned: scannedCount
        });
        
        // Generate recommendations
        const recommendations = reportBuilder.generateRecommendations(allFindings);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                message: 'Webpage scan complete',
                sourceUrl: url,
                scriptsScanned: scannedCount,
                findings: report.findings,
                summary: report.summary,
                recommendations
            })
        };

    } catch (err) {
        console.error('Scan error:', err);
        
        // Handle timeout specifically
        if (err.message.includes('timeout')) {
            return {
                statusCode: 408,
                headers,
                body: JSON.stringify({ 
                    error: 'Scan timeout - webpage too complex or has too many scripts',
                    details: err.message
                })
            };
        }
        
        // Handle other specific errors
        if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ 
                    error: 'Cannot reach the specified URL',
                    details: `Network error: ${err.message}`
                })
            };
        }
        
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
