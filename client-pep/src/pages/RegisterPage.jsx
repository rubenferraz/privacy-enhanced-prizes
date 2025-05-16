import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

const API_URL = 'http://localhost:8000/auth'

function RegisterPage() {
  const [registerUsername, setRegisterUsername] = useState('')
  const [registerPassword, setRegisterPassword] = useState('')
  const [registerMsg, setRegisterMsg] = useState('')
  const navigate = useNavigate()

  // Redirect to scratchcard if already logged in
  useEffect(() => {
    if (localStorage.getItem('token')) {
      navigate('/scratchcard')
    }
  }, [navigate])

  async function handleRegister(e) {
    e.preventDefault()
    setRegisterMsg('...')

    let DH_P, DH_G
    try {
      // 0. Fetch DH parameters from backend
      const params = await fetch(`${API_URL}/dh/params`).then(res => res.json())
      DH_P = parseInt(params.p)
      DH_G = parseInt(params.g)

      // 1. Get server public key (as integer)
      const dhStart = await fetch(`${API_URL}/dh/start`).then(res => res.json())
      const serverPubKey = parseInt(dhStart.server_pub_key)

      // 2. Generate client private/public key (random int)
      const clientPrivate = Math.floor(Math.random() * (DH_P - 2)) + 2
      const clientPublic = Math.pow(DH_G, clientPrivate) % DH_P

      // 3. Send client public key to server
      await fetch(`${API_URL}/dh/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: registerUsername, client_pub_key: clientPublic.toString() })
      })

      // 4. Derive shared key (as int, pad to 16 bytes)
      const shared = Math.pow(serverPubKey, clientPrivate) % DH_P
      const sharedBytes = new Uint8Array(16)
      sharedBytes.set([shared], 15) // put shared at the end (big endian)

      // 5. Encrypt password with AES-GCM using sharedBytes as key
      const enc = new TextEncoder()
      const iv = window.crypto.getRandomValues(new Uint8Array(12))
      const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        sharedBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      )
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        enc.encode(registerPassword)
      )
      const ciphertextB64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)))
      const ivB64 = btoa(String.fromCharCode(...iv))

      // 6. Register
      const res = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: registerUsername,
          encrypted_password: ciphertextB64,
          nonce: ivB64
        }),
      })

      const data = await res.json()
      setRegisterMsg(data.message || data.error || 'Erro')
    } catch (err) {
      setRegisterMsg(err.message || 'Erro de rede')
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
      <div className="mt-4 text-center flex items-center justify-center"> 
        <p className='text-zinc-200 lowercase tracking-wide font-extralight bg-zinc-200/10 px-2 py-1 rounded'>
            {registerMsg}
        </p>
      </div>
    </div>
  )
}

export default RegisterPage