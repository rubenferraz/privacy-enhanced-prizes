import { Link, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'

function Navbar() {
  const [loggedIn, setLoggedIn] = useState(!!localStorage.getItem('token'))
  const navigate = useNavigate()

  useEffect(() => {
    function sync() {
      setLoggedIn(!!localStorage.getItem('token'))
    }
    
    // Handle both storage event (for cross-tab) and custom auth event (for same-tab)
    window.addEventListener('storage', sync)
    window.addEventListener('auth-change', sync)
    
    return () => {
      window.removeEventListener('storage', sync)
      window.removeEventListener('auth-change', sync)
    }
  }, [])

  async function handleLogout() {
    const token = localStorage.getItem('token')
    if (token) {
      try {
        await fetch('http://localhost:8000/auth/logout?token=' + encodeURIComponent(token))
      } catch {}
      localStorage.removeItem('token')
      localStorage.removeItem('scratchcard_history')
      setLoggedIn(false)
      // Dispatch custom event to notify other components
      window.dispatchEvent(new Event('auth-change'))
      navigate('/login')
    }
  }

  return (
    <nav className="flex gap-4 p-4 bg-zinc-950 border-b mb-8 items-center justify-between">
      <div className='flex gap-4 items-center'>
      <Link to="/" className="text-zinc-300 hover:text-zinc-100 lowercase tracking-wide transition-colors duration-300">Início</Link>
      {!loggedIn && (
        <>
          <Link to="/register" className="bg-sky-950 px-2 py-1 rounded text-zinc-400 hover:text-zinc-200 lowercase tracking-wide hover:bg-sky-900 transition-colors duration-300">Registo</Link>
          <Link to="/login" className="bg-sky-950 px-2 py-1 rounded text-zinc-400 hover:text-zinc-200 lowercase tracking-wide hover:bg-sky-900 transition-colors duration-300">Login (ZKP)</Link>
        </>
      )}
      {loggedIn && (
        <>
          <Link to="/scratchcard" className="bg-sky-950 px-2 py-1 rounded text-zinc-400 hover:text-zinc-200 lowercase tracking-wide hover:bg-sky-900 transition-colors duration-300">Raspadinhas</Link>
        </>
      )}
      </div>
      {loggedIn && (
         <button
            className="bg-red-700 text-white px-3 py-1 rounded text-xs hover:bg-red-800 ml-2 transition-colors duration-300"
            onClick={handleLogout}
          >
            Terminar a sessão
          </button>
      )}
    </nav>
  )
}

export default Navbar
