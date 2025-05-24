import { Routes, Route } from 'react-router-dom'
import RegisterPage from './pages/RegisterPage'
import LoginPage from './pages/LoginPage'
import HomePage from './pages/HomePage'
import ScratchcardPage from './pages/ScratchcardPage'

function App() {
  return (
    <div className='bg-zinc-800 min-h-screen'>
      <div>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/scratchcard" element={<ScratchcardPage />} />
          <Route path="*" element={
            <div className="text-center p-8 flex items-center justify-center flex-col min-h-screen">
              <div className="text-red-500 text-lg mb-4 font-bold tracking-widest uppercase">Página não encontrada</div>
              <button 
                onClick={() => window.location.href = '/'}
                className="text-zinc-200 px-4 py-2 font-bold text-xs"
              >
                Voltar ao início
              </button>
            </div>
          } />
        </Routes>
      </div>
    </div>
  )
}

export default App
