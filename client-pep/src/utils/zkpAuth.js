import { fetchWithMAC } from './mac';
import { generateKeys, generateProof, computeResponse } from './zkp';

const API_URL = 'https://localhost:8000/auth';

// Fetch ZKP parameters from the server
export async function getZkpParams() {
  try {
    const response = await fetchWithMAC(`${API_URL}/zkp/params`, {
      method: 'GET',
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch ZKP parameters');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching ZKP parameters:', error);
    throw error;
  }
}

// Initiate ZKP login - Step 1: Send username and public key
export async function initiateZkpLogin(username, password) {
  try {
    // First, get ZKP parameters
    const { p, q, g } = await getZkpParams();
    
    // Generate the user's public key from their password
    const y = generateKeys(password, p, q, g);
    
    // Generate the first part of the proof
    const { v, r } = generateProof(password, p, q, g);
    
    // Store v in session storage temporarily to use in the next step
    // (This should be handled more securely in a production environment)
    sessionStorage.setItem('zkp_v', v.toString());
    
    // Send the username, public key, and r to the server
    const response = await fetchWithMAC(`${API_URL}/zkp/login/init`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        public_key: y.toString(),
        r,
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to initiate ZKP login');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error initiating ZKP login:', error);
    throw error;
  }
}

// Complete ZKP login - Step 2: Send the response to the challenge
export async function completeZkpLogin(username, password, challenge) {
  try {
    // Get ZKP parameters
    const { q } = await getZkpParams();
    
    // Retrieve v from session storage
    const v = BigInt(sessionStorage.getItem('zkp_v'));
    
    // Clear v from session storage for security
    sessionStorage.removeItem('zkp_v');
    
    // Compute the response to the challenge
    const s = computeResponse(v, challenge, password, q);
    
    // Send the response to the server
    const response = await fetchWithMAC(`${API_URL}/zkp/login/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        s: s.toString(),
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to verify ZKP login');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error completing ZKP login:', error);
    throw error;
  }
}
