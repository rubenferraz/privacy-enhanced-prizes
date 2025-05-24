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
      window.dispatchEvent(new Event('auth-change'))
      navigate('/')
    }
  }

  return (
    <nav className="flex gap-4 p-4 bg-zinc-950 items-center justify-between">
      <div className="flex items-center">
        <Link to="/" className="text-amber-400 font-semibold hover:text-amber-300 transition-colors duration-300">
          PrivacyEnhancedPrizes
        </Link>
      </div>
      
      {loggedIn && (
        <div className="flex items-center gap-2">
          <button
            className="bg-zinc-700 text-zinc-100 px-4 py-1 hover:bg-zinc-600 transition-colors duration-300"
            onClick={handleLogout}
          >
            Sair
          </button>
        </div>
      )}
    </nav>
  )
}

export default Navbar
