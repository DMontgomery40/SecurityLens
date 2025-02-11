export async function handler(event, context) {
  // ... your scanning logic which determines the total and scanned items
  // For demonstration, here's a static response:
  return {
    statusCode: 200,
    body: JSON.stringify({
      scanned: 20,  // update dynamically
      total: 100,   // update dynamically
    }),
  };
} 