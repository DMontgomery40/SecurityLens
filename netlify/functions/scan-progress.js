export const handler = async (event, context) => {
  if (event.requestContext.eventType === 'CONNECT') {
    // Handle WebSocket connection
    return {
      statusCode: 200,
      body: 'Connected'
    };
  }

  if (event.requestContext.eventType === 'DISCONNECT') {
    // Handle WebSocket disconnection
    return {
      statusCode: 200,
      body: 'Disconnected'
    };
  }

  if (event.requestContext.eventType === 'MESSAGE') {
    // Handle incoming messages (if needed)
    return {
      statusCode: 200,
      body: 'Message received'
    };
  }

  return {
    statusCode: 400,
    body: 'Unknown event type'
  };
}; 