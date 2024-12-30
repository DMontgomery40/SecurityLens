import { getProgressForScan } from './utils/progressHandler.js';

export const handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers
    };
  }

  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const scanId = event.queryStringParameters?.scanId;
    
    if (!scanId) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Scan ID is required' })
      };
    }

    const progress = await getProgressForScan(scanId);
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(progress)
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
};