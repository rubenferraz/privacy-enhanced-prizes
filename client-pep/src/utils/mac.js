/**
 * MAC utility functions for client-side verification and generation
 */

// Same secret as server for simplicity (in real world, this would need better security)
const MAC_SECRET = "8f39e7bc45d2a7c18b1d9e5a7d3426f9";

/**
 * Generate HMAC-SHA256 for given data
 */
export async function generateMAC(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));
  const secretBuffer = encoder.encode(MAC_SECRET);
  
  // Import key for HMAC
  const key = await window.crypto.subtle.importKey(
    "raw",
    secretBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  // Generate signature
  const signature = await window.crypto.subtle.sign(
    "HMAC",
    key,
    dataBuffer
  );
  
  // Convert to base64
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

/**
 * Verify if MAC matches the data
 */
export async function verifyMAC(data, mac) {
  const calculatedMAC = await generateMAC(data);
  return calculatedMAC === mac;
}

/**
 * Enhanced fetch that adds and verifies MACs
 */
export async function fetchWithMAC(url, options = {}) {
  // Clone options
  const fetchOptions = { ...options };
  fetchOptions.headers = { ...fetchOptions.headers };
  
  // Add MAC to request if it has a body
  if (fetchOptions.body) {
    const bodyString = typeof fetchOptions.body === 'string' 
      ? fetchOptions.body 
      : JSON.stringify(fetchOptions.body);
      
    const mac = await generateMAC(bodyString);
    fetchOptions.headers["X-MAC"] = mac;
    console.log(`[MAC] Added MAC to request for ${url}`, mac.substring(0, 10) + "...");
  }
  
  // Perform fetch
  const response = await fetch(url, fetchOptions);
  
  // DEBUGGING - Log all headers
  console.log(`[MAC Debug] Response headers for ${url}:`, 
    Array.from(response.headers.entries())
      .map(([k,v]) => `${k}: ${v.substring(0,20)}${v.length > 20 ? '...' : ''}`)
      .join(', ')
  );
  
  // Verify response MAC if present
  const responseMac = response.headers.get("X-MAC");
  if (responseMac) {
    console.log(`[MAC] Received MAC in response from ${url}`, responseMac.substring(0, 10) + "...");
    const responseClone = response.clone();
    const responseText = await responseClone.text();
    
    const isValid = await verifyMAC(responseText, responseMac);
    console.log(`[MAC] Response MAC verification: ${isValid ? "SUCCESS" : "FAILED"}`);
    
    // Parse and return JSON if possible
    try {
      const json = JSON.parse(responseText);
      return {
        ...response,
        json: () => Promise.resolve(json),
        text: () => Promise.resolve(responseText)
      };
    } catch (e) {
      return {
        ...response,
        text: () => Promise.resolve(responseText)
      };
    }
  }
  
  // If no MAC header, just return the response as is
  return response;
}
