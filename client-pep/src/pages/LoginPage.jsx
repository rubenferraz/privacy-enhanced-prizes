import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchWithMAC } from '../utils/mac'

const API_URL = 'https://localhost:8000/auth'

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
    setLoginMsg('A processar...')
    setToken('')

    try {
      const res = await fetchWithMAC(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword
        }),
      });

      const data = await res.json();
      
      if (res.ok && data.token) {
        setLoginMsg('Login bem-sucedido!')
        setToken(data.token)
        localStorage.setItem('token', data.token)
        navigate('/scratchcard')
      } else {
        setLoginMsg(data.detail || 'Credenciais inválidas')
      }
    } catch (err) {
      console.error('Login error:', err)
      setLoginMsg('Erro ao tentar fazer login')
    }
  }

  return (
    <div className="max-w-md mx-auto mt-16 p-8 bg-zinc-900 rounded shadow">
      <h2 className="text-2xl font-extralight mb-3 text-zinc-100 tracking-wide uppercase">Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide"
          placeholder="username"
          value={loginUsername}
          onChange={e => setLoginUsername(e.target.value)}
          required
        />
        <input
          className="border rounded px-3 py-2 text-zinc-400 tracking-wide"
          placeholder="password"
          type="password"
          value={loginPassword}
          onChange={e => setLoginPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-sky-950 font-extralight text-white rounded px-4 py-2 hover:bg-sky-900 transition"
        >
          <span className='uppercase tracking-wide text-xs'>Login</span>
        </button>
      </form>
      <div className="mt-4 text-center">
        <p className="text-zinc-400 text-sm">
          Não tem conta? <span onClick={() => navigate('/register')} className="text-sky-400 cursor-pointer hover:underline">Registar</span>
        </p>
      </div>
      
      {token && (
        <div className="mt-4 p-3 bg-green-700/20 rounded">
          <p className="text-green-300 text-sm">Login efetuado com sucesso!</p>
        </div>
      )}
      
      {!token && loginMsg && (
        <div className="mt-4 text-center flex items-center justify-center">
          <p className='text-zinc-200 lowercase tracking-wide font-extralight bg-zinc-200/10 px-2 py-1 rounded'>
            {loginMsg}
          </p>
        </div>
      )}
    </div>
  );
}

export default LoginPage;