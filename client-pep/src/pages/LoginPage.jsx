import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchWithMAC } from '../utils/mac'
import { FaArrowLeft } from 'react-icons/fa'

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
    <div className='flex flex-col items-center justify-center min-h-screen py-12'>
    {/* back to home page */}
      <div className='text-start container max-w-lg mb-2'>
        <button 
          onClick={() => navigate('/')}
          className="mt-0 text-zinc-200 cursor-pointer transition-colors duration-300 font-bold tracking-wide uppercase text-xs"
        >
          {/* arrow icon */}
          <FaArrowLeft className="inline mr-2 text-xs" />
            Voltar ao início
        </button>
      </div>
      <div className="container max-w-lg p-8 bg-zinc-900 rounded shadow">
      <h2 className="text-2xl font-extralight mb-3 text-zinc-100 tracking-wide uppercase">Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="border-b-1 border-zinc-700 hover:text-zinc-300 hover:border-zinc-500 px-3 py-2 text-zinc-400 tracking-wide transition-colors duration-300"
          placeholder="username"
          value={loginUsername}
          onChange={e => setLoginUsername(e.target.value)}
          required
        />
        <input
          className="border-b-1 border-zinc-700 hover:text-zinc-300 hover:border-zinc-500 px-3 py-2 text-zinc-400 tracking-wide transition-colors duration-300"
          placeholder="password"
          type="password"
          value={loginPassword}
          onChange={e => setLoginPassword(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-zinc-700 font-extralight text-white cursor-pointer border-b-2 border-transparent hover:border-amber-400 px-4 py-2 hover:bg-zinc-800 transition-all duration-300"
        >
          <span className='uppercase font-bold tracking-wide text-xs'>Login</span>
        </button>
      </form>
      <div className="mt-4 text-center">
        <p className="text-zinc-400 text-sm">
          Não tem conta? <span onClick={() => navigate('/register')} className="text-zinc-300 cursor-pointer hover:underline">Registe-se</span>
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
    </div>
  );
}

export default LoginPage;