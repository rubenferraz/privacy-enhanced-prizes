import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import * as bigintConversion from 'bigint-conversion'

const API_URL = 'http://localhost:8000/auth'

// For standard Diffie-Hellman in the browser
class DHBrowser {
  constructor(p, g) {
    this.p = BigInt(p);
    this.g = BigInt(g);
    this.privateKey = null;
    this.publicKey = null;
  }

  generateKeys() {
    // Generate a random private key (256 bits should be sufficient)
    const privateKeyBytes = new Uint8Array(32);
    window.crypto.getRandomValues(privateKeyBytes);
    this.privateKey = this._bytesToBigInt(privateKeyBytes);
    
    // Ensure privateKey is in range [2, p-2]
    this.privateKey = this.privateKey % (this.p - BigInt(3)) + BigInt(2);
    
    // Generate public key: g^privateKey mod p
    this.publicKey = this._modPow(this.g, this.privateKey, this.p);
    
    return {
      privateKey: this.privateKey.toString(),
      publicKey: this.publicKey.toString()
    };
  }

  computeSharedSecret(otherPublicKey) {
    const otherPublicKeyBigInt = BigInt(otherPublicKey);
    // Compute shared secret: otherPublicKey^privateKey mod p
    const sharedSecret = this._modPow(otherPublicKeyBigInt, this.privateKey, this.p);
    return sharedSecret;
  }

  // Helper for modular exponentiation (a^b mod n)
  _modPow(a, b, n) {
    a = a % n;
    let result = BigInt(1);
    let x = a;
    
    while (b > 0) {
      const lsb = b % BigInt(2);
      b = b / BigInt(2);
      
      if (lsb === BigInt(1)) {
        result = (result * x) % n;
      }
      
      x = (x * x) % n;
    }
    
    return result;
  }

  // Convert Uint8Array to BigInt
  _bytesToBigInt(bytes) {
    let result = BigInt(0);
    for (let i = 0; i < bytes.length; i++) {
      result = result << BigInt(8);
      result = result + BigInt(bytes[i]);
    }
    return result;
  }
  
  // Convert BigInt to fixed-length bytes (32 bytes = 256 bits)
  getBytesFromBigInt(bigInt) {
    const hex = bigInt.toString(16).padStart(64, '0');
    const result = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      result[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return result;
  }
}

// Helper function to convert BigInt to Uint8Array with proper size
function bigintToUint8Array(bigintValue) {
  // Calculate how many bytes we need
  const byteLength = Math.ceil(bigintValue.toString(16).length / 2);
  const result = new Uint8Array(byteLength);
  
  let tempValue = bigintValue;
  for (let i = byteLength - 1; i >= 0; i--) {
    result[i] = Number(tempValue & BigInt(0xff));
    tempValue = tempValue >> BigInt(8);
  }
  
  return result;
}

function RegisterPage() {
  const [registerUsername, setRegisterUsername] = useState('')
  const [registerPassword, setRegisterPassword] = useState('')
  const [registerMsg, setRegisterMsg] = useState('')
  const [registrationSuccess, setRegistrationSuccess] = useState(false)
  const navigate = useNavigate()

  // Redirect to scratchcard if already logged in
  useEffect(() => {
    if (localStorage.getItem('token')) {
      navigate('/scratchcard')
    }
  }, [navigate])

  async function handleRegister(e) {
    e.preventDefault()
    setRegisterMsg('Processando...')

    try {
      // 1. Fetch DH parameters from backend
      const params = await fetch(`${API_URL}/dh/params`).then(res => res.json())
      const pBase64 = params.p; // Base64 encoded p value
      const g = params.g; // g value as number
      
      // Decode p from base64
      const pBinary = atob(pBase64);
      const pBytes = new Uint8Array(pBinary.length);
      for (let i = 0; i < pBinary.length; i++) {
        pBytes[i] = pBinary.charCodeAt(i);
      }
      
      // Convert bytes to bigint
      let pBigInt = BigInt(0);
      for (let i = 0; i < pBytes.length; i++) {
        pBigInt = (pBigInt << BigInt(8)) + BigInt(pBytes[i]);
      }
      
      // 2. Initialize DH with parameters
      const dh = new DHBrowser(pBigInt, g);
      
      // 3. Generate client keys
      const keys = dh.generateKeys();
      
      // 4. Get server's public key
      const dhStart = await fetch(`${API_URL}/dh/start`).then(res => res.json());
      const serverPublicKeyPEM = dhStart.server_pub_key;
      
      // Extract the server public key value from PEM format
      const pemContents = serverPublicKeyPEM
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\n/g, '');
      
      // Convert client public key to PEM format for server (to maintain compatibility)
      const clientPublicKeyBytes = bigintToUint8Array(dh.publicKey);
      const clientPublicKeyBase64 = btoa(String.fromCharCode(...clientPublicKeyBytes));
      const clientPublicKeyPEM = `-----BEGIN PUBLIC KEY-----\n${clientPublicKeyBase64}\n-----END PUBLIC KEY-----`;
      
      // Send client public key to server
      const dhFinishResponse = await fetch(`${API_URL}/dh/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: registerUsername,
          client_pub_key: clientPublicKeyPEM
        })
      });
      
      if (!dhFinishResponse.ok) {
        throw new Error('Failed to establish DH key');
      }
      
      // 5. Calculate shared secret
      // Decode server's public key from base64
      const serverPublicKeyBinary = atob(pemContents);
      const serverPublicKeyBytes = new Uint8Array(serverPublicKeyBinary.length);
      for (let i = 0; i < serverPublicKeyBinary.length; i++) {
        serverPublicKeyBytes[i] = serverPublicKeyBinary.charCodeAt(i);
      }
      
      // Convert to bigint for computation
      let serverPublicKeyBigInt = BigInt(0);
      for (let i = 0; i < serverPublicKeyBytes.length; i++) {
        serverPublicKeyBigInt = (serverPublicKeyBigInt << BigInt(8)) + BigInt(serverPublicKeyBytes[i]);
      }
      
      const sharedSecretBigInt = dh.computeSharedSecret(serverPublicKeyBigInt);
      
      // 6. Hash the shared secret to get a 256-bit key
      const sharedSecretBytes = bigintToUint8Array(sharedSecretBigInt);
      const sharedSecretBuffer = await crypto.subtle.digest('SHA-256', sharedSecretBytes);
      const aesKeyBytes = new Uint8Array(sharedSecretBuffer);
      
      // 7. Import as AES-GCM key
      const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        aesKeyBytes,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      
      // 8. Encrypt password
      const enc = new TextEncoder();
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        enc.encode(registerPassword)
      );
      
      const ciphertextB64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
      const ivB64 = btoa(String.fromCharCode(...iv));

      // 9. Register with encrypted password
      const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: registerUsername,
          encrypted_password: ciphertextB64,
          nonce: ivB64
        }),
      });

      const data = await res.json();
      if (res.ok) {
        setRegisterMsg('Registo efetuado com sucesso');
        setRegistrationSuccess(true);
      } else {
        setRegisterMsg(data.detail || data.error || 'Erro');
      }
    } catch (err) {
      console.error("Registration error:", err);
      setRegisterMsg(err.message || 'Erro de rede');
    }
  }

  return (
    <div className="max-w-md mx-auto mt-16 p-8 bg-zinc-900 rounded shadow">
      <h2 className="text-2xl font-extralight mb-3 text-zinc-100 tracking-wide uppercase">Registo</h2>
      <form onSubmit={handleRegister} className="flex flex-col gap-4">
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide"
          placeholder="username"
          value={registerUsername}
          onChange={e => setRegisterUsername(e.target.value)}
          required
        />
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide"
          placeholder="password"
          type="password"
          value={registerPassword}
          onChange={e => setRegisterPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-sky-950 font-extralight text-white rounded px-4 py-2 hover:bg-sky-900 transition"
        >
          <span className='uppercase tracking-wide text-xs'>Registar</span>
        </button>
      </form>
      <div className="mt-4 text-center">
        <p className="text-zinc-400 text-sm">
          Já tem conta? <span onClick={() => navigate('/login')} className="text-sky-400 cursor-pointer hover:underline">Login</span>
        </p>
      </div>
      
      {registrationSuccess && (
        <div className="mt-4 text-center">
          <div className="bg-green-700/20 p-3 rounded">
            <p className="text-green-300 mb-2">Registo efetuado com sucesso!</p>
            <button 
              onClick={() => navigate('/login')} 
              className="bg-sky-950 font-bold text-white rounded px-4 py-2 hover:bg-sky-900 transition"
            >
              <span className='lowercase tracking-wide text-xs'>Fazer Login</span>
            </button>
          </div>
        </div>
      )}
      
      <div className="mt-4 text-center flex items-center justify-center"> 
        <p className='text-zinc-200 lowercase tracking-wide font-extralight bg-zinc-200/10 px-2 py-1 rounded'>
            {!registrationSuccess && registerMsg}
        </p>
      </div>
    </div>
  )
}

export default RegisterPage