/* eslint-env node */
import { getProgressForScan } from './utils/progressHandler.js';
import { SecurityLensError } from '../../src/lib/errors.js';
import {
  createFunctionContext,
  errorResponse,
  jsonResponse,
  methodNotAllowedResponse,
  optionsResponse
} from './utils/http.js';

export const handler = async (event) => {
  const { headers, logger, requestId } = createFunctionContext('scan-progress', event, {
    allowMethods: 'GET, OPTIONS'
  });

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return optionsResponse(headers);
  }

  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return methodNotAllowedResponse(headers);
  }

  try {
    const scanId = event.queryStringParameters?.scanId;
    
    if (!scanId) {
      throw new SecurityLensError('Missing scanId parameter', {
        code: 'MISSING_SCAN_ID',
        status: 400,
        requestId,
        userMessage: 'Missing scanId parameter'
      });
    }

    const progress = await getProgressForScan(scanId);

    logger.debug(
      {
        scanId,
        status: progress.status
      },
      'Returning scan progress'
    );
    
    return jsonResponse(200, headers, {
      ...progress,
      requestId,
      timestamp: Date.now()
    });
  } catch (error) {
    return errorResponse(error, headers, logger);
  }
};
