import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { FaShieldAlt, FaLock, FaStar, FaInfoCircle, FaSignOutAlt } from 'react-icons/fa'

function HomePage() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('token'))
  const navigate = useNavigate()

  useEffect(() => {
    function syncToken() {
      setIsLoggedIn(!!localStorage.getItem('token'))
    }
    window.addEventListener('storage', syncToken)
    syncToken()
    return () => window.removeEventListener('storage', syncToken)
  }, [])

  // Add logout handler
  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await fetch(`https://localhost:8000/auth/logout?token=${encodeURIComponent(token)}`);
        localStorage.removeItem('token');
        localStorage.removeItem('scratchcard_history');
        setIsLoggedIn(false);
      }
    } catch (err) {
      console.error('Logout error:', err);
      localStorage.removeItem('token');
      localStorage.removeItem('scratchcard_history');
      setIsLoggedIn(false);
    }
  };

  return (
    <div className='flex flex-col items-center justify-center min-h-screen bg-gradient-to-b from-zinc-900 to-zinc-950 py-12'>
      <div className="max-w-3xl mx-auto px-4 relative">
        <div className="relative bg-zinc-900/80 backdrop-blur-sm p-8 border border-zinc-800 overflow-hidden">
          {/* Decorative pattern overlay */}
          <div className="absolute inset-0 opacity-5 pointer-events-none">
            <div className="absolute inset-0" style={{
              backgroundImage: `
                radial-gradient(circle at 25% 25%, white 1px, transparent 1px),
                radial-gradient(circle at 75% 75%, white 1px, transparent 1px)
              `,
              backgroundSize: '20px 20px'
            }}></div>
          </div>
          
          {/* Security icon */}
          {/* <div className="flex justify-center mb-4">
            <div className="bg-amber-400/20 p-3">
              <FaShieldAlt className="h-10 w-10 text-amber-400" />
            </div>
          </div> */}

          <h1 className="text-center text-5xl font-light mb-2 text-gradient bg-gradient-to-r from-amber-300 via-amber-400 to-amber-600 bg-clip-text text-transparent tracking-tight">
            PrivacyEnhanced<span className="font-bold">Prizes</span>
          </h1>
          
          <p className="text-center text-base font-light text-zinc-400 mb-6 max-w-lg mx-auto">
            Plataforma de raspadinhas digitais com privacidade e segurança.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-zinc-800/50 p-4 rounded">
              <div className="text-zinc-400 mb-2 flex justify-center">
                <FaLock size={24} />
              </div>
              <h3 className="text-zinc-200 text-lg mb-1 text-center">Segurança</h3>
              <p className="text-zinc-400 text-sm text-center">Todas as transações são protegidas.</p>
            </div>
            <div className="bg-zinc-800/50 p-4 rounded">
              <div className="text-zinc-400 mb-2 flex justify-center">
                <FaShieldAlt size={24} />
              </div>
              <h3 className="text-zinc-200 text-lg mb-1 text-center">Privacidade</h3>
              <p className="text-zinc-400 text-sm text-center">Os seus dados e escolhas são mantidos privados.</p>
            </div>
            <div className="bg-zinc-800/50 p-4 rounded">
              <div className="text-zinc-400 mb-2 flex justify-center">
                <FaStar size={24} />
              </div>
              <h3 className="text-zinc-200 text-lg mb-1 text-center">Divertido</h3>
              <p className="text-zinc-400 text-sm text-center">Raspe e ganhe prémios!</p>
            </div>
          </div>
          
          {!isLoggedIn && (
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <button 
                onClick={() => navigate('/register')} 
                className="bg-zinc-700 font-extralight px-8 py-3 text-zinc-200 hover:text-zinc-100 tracking-wide hover:bg-zinc-600 transition-all duration-300 border-b-2 border-transparent hover:border-amber-400 cursor-pointer"
              >
                <span className="uppercase font-bold tracking-wide text-sm">Registo</span>
              </button>
              <button 
                onClick={() => navigate('/login')} 
                className="bg-amber-500 hover:bg-amber-600 text-zinc-900 font-bold px-8 py-3 tracking-wide transition-all duration-300 shadow-amber-500/20 hover:shadow-amber-500/40 cursor-pointer"
              >
                <span className="uppercase tracking-wide text-sm">Entrar</span>
              </button>
            </div>
          )}
          
          {isLoggedIn && (
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <button 
                onClick={() => navigate('/scratchcard')} 
                className="bg-amber-500 hover:bg-amber-600 text-zinc-900 font-bold px-8 py-3 tracking-wide transition-all duration-300 shadow-amber-500/20 hover:shadow-amber-500/40 cursor-pointer"
              >
                <span className="uppercase tracking-wide text-sm">Ir para as Raspadinhas</span>
              </button>
              {/* Add logout button */}
              <button 
                onClick={handleLogout}
                className="bg-zinc-700 hover:bg-zinc-600 text-zinc-300 font-extralight px-4 py-3 tracking-wide transition-all duration-300 border-b-2 border-transparent hover:border-red-400 cursor-pointer"
              >
                <div className="flex items-center gap-2 justify-center">
                  <FaSignOutAlt size={14} />
                  <span className="uppercase tracking-wide text-sm">Sair</span>
                </div>
              </button>
            </div>
          )}
          
          {/* <div className="mt-8 text-xs text-zinc-500 flex items-center justify-center">
            <FaInfoCircle className="h-4 w-4 mr-1" />
            Tecnologia protegida por criptografia de ponta a ponta
          </div> */}
        </div>
      </div>
    </div>
  )
}

// Required for gradient text in Tailwind
const style = document.createElement('style')
style.innerHTML = `
  .text-gradient {
    -webkit-background-clip: text;
    background-clip: text;
  }
`
document.head.appendChild(style)

export default HomePage
