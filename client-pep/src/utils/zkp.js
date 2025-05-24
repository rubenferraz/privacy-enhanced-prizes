import CryptoJS from 'crypto-js';

// Convert a secret string to a numeric value
function toSecretInt(secret, q) {
  const hash = CryptoJS.SHA256(secret).toString();
  // Convert to BigInt and then use modulo q to get within the proper range
  return BigInt('0x' + hash) % BigInt(q);
}

// Generate the public key based on a secret (password)
function generateKeys(secret, p, q, g) {
  const x = toSecretInt(secret, q);
  return modPow(BigInt(g), x, BigInt(p));
}

// Generate proof components for ZKP
function generateProof(secret, p, q, g) {
  // Generate random v
  const v = generateRandomBigInt(q);
  // Calculate r = g^v mod p
  const r = modPow(BigInt(g), v, BigInt(p));
  return { v, r: r.toString() };
}

// Compute response for challenge in ZKP
function computeResponse(v, c, secret, q) {
  const x = toSecretInt(secret, q);
  // s = (v + c * x) mod q
  return (v + BigInt(c) * x) % BigInt(q);
}

// Helper function for modular exponentiation (a^b mod n)
function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  
  let result = 1n;
  base = base % modulus;
  
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  
  return result;
}

// Generate a random BigInt less than n
function generateRandomBigInt(n) {
  // Generate random bytes with sufficient entropy
  const nBytes = Math.ceil(BigInt(n).toString(2).length / 8);
  const randValues = new Uint8Array(nBytes);
  window.crypto.getRandomValues(randValues);
  
  // Convert to BigInt and ensure it's less than n
  let result = 0n;
  for (const byte of randValues) {
    result = (result << 8n) | BigInt(byte);
  }
  
  return result % BigInt(n);
}

export {
  toSecretInt,
  generateKeys,
  generateProof,
  computeResponse,
  modPow
};