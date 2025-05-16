import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

const API_URL = 'http://localhost:8000/auth'

function LoginPage() {
  const [loginUsername, setLoginUsername] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginMsg, setLoginMsg] = useState('')
  const [token, setToken] = useState('')
  const navigate = useNavigate()

  // Redirect to scratchcard if already logged in
  useEffect(() => {
    if (localStorage.getItem('token')) {
      navigate('/scratchcard')
    }
  }, [navigate])

  async function handleLogin(e) {
    e.preventDefault()
    setLoginMsg('...')
    setToken('')

    try {
      // 0. Fetch DH parameters
      const params = await fetch(`${API_URL}/dh/params`).then(res => res.json())
      const DH_P = parseInt(params.p)
      const DH_G = parseInt(params.g)

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
        body: JSON.stringify({ username: loginUsername, client_pub_key: clientPublic.toString() })
      })

      // 4. Derive shared key (as int, pad to 16 bytes)
      const shared = Math.pow(serverPubKey, clientPrivate) % DH_P
      const sharedBytes = new Uint8Array(16)
      sharedBytes.set([shared], 15)

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
        enc.encode(loginPassword)
      )
      // Concatenate IV + ciphertext and base64 encode
      const encryptedBytes = new Uint8Array([...iv, ...new Uint8Array(encrypted)])
      const encryptedPassword = btoa(String.fromCharCode(...encryptedBytes))

      // 6. Login
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: encryptedPassword }),
      })

      const data = await res.json()
      if (res.ok) {
        setLoginMsg('Login OK')
        setToken(data.token)
        localStorage.setItem('token', data.token)
        navigate('/scratchcard')
        // setTimeout(() => navigate('/scratchcard'), 300)
      } else {
        setLoginMsg(data.detail || 'Falha na autenticação')
      }
    } catch (err) {
      console.error(err)
      setLoginMsg('Erro de rede')
    }
  }

  return (
    <div className="max-w-md mx-auto mt-16 p-8 bg-zinc-900 rounded shadow relative">
      <div className="absolute top-2 right-2 z-10">
        <p className='text-zinc-200 lowercase tracking-wide font-extralight bg-emerald-300/10 px-2 py-1 rounded'>
           {loginMsg}
        </p>
      </div>
      <h2 className="text-2xl font-extralight mb-3 text-zinc-100 tracking-wide uppercase">Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide lowercase"
          placeholder="Username"
          value={loginUsername}
          onChange={e => setLoginUsername(e.target.value)}
          required
        />
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide lowercase"
          placeholder="Password"
          type="password"
          value={loginPassword}
          onChange={e => setLoginPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-sky-950 font-bold text-white rounded px-4 py-2 hover:bg-sky-900 transition"
        >
          <span className='lowercase tracking-wide text-xs'>login</span>
        </button>
      </form>
      {token && (
        <div className="mt-4 break-all bg-zinc-200 p-2 rounded text-xs">
          <b className=''>your JW Token:</b>
          <p className='font-mono bg-zinc-50 px-2 py-1 rounded mt-1'>{token}</p>
        </div>
      )}
    </div>
  )
}

export default LoginPage