import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

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

  return (
    <div className='flex flex-col items-center justify-center'>
      <div className="max-w-xl mx-auto mt-40 p-8 bg-zinc-900 rounded shadow text-center">
        <h1 className="text-4xl font-semibold mb-4 text-zinc-200 tracking-wide">PrivacyEnhancedPrizes</h1>
        <p className="text-lg font-light text-zinc-300 mb-6">
          Bem-vindo ao distribuidor de raspadinhas digitais seguras.<br />
          {/* <span className="font-extralight text-zinc-400">{isLoggedIn ? 'Clique na opção Scratchcard para jogar.' : 'Use o menu acima para se registar ou autenticar.'}</span> */}
        </p>
        
        {!isLoggedIn && (
          <div className="mt-0 space-y-2">
            <button 
              onClick={() => navigate('/register')} 
              className="mx-2 bg-sky-950 px-4 py-2 rounded text-zinc-300 hover:text-zinc-100 lowercase tracking-wide hover:bg-sky-900 transition-colors duration-300"
            >
              Registo
            </button>
            <button 
              onClick={() => navigate('/login')} 
              className="mx-2 bg-sky-950 px-4 py-2 rounded text-zinc-300 hover:text-zinc-100 lowercase tracking-wide hover:bg-sky-900 transition-colors duration-300"
            >
              Login
            </button>
          </div>
        )}
        
        {isLoggedIn && (
          <button 
            onClick={() => navigate('/scratchcard')} 
            className="mt-0 bg-sky-950 px-4 py-2 rounded text-zinc-300 hover:text-zinc-100 tracking-wide hover:bg-sky-900 transition-colors duration-300"
          >
            Ir para as Raspadinhas
          </button>
        )}
      </div>
    </div>
  )
}

export default HomePage
