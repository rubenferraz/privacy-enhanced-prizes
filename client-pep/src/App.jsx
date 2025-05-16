import { useState } from 'react'
import { Routes, Route } from 'react-router-dom'
import RegisterPage from './pages/RegisterPage'
import LoginPage from './pages/LoginPage'
import HomePage from './pages/HomePage'
import ScratchcardPage from './pages/ScratchcardPage'
import Navbar from './components/Navbar'

function App() {
  return (
    <div className='bg-zinc-800 min-h-screen'>
      <Navbar />
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/scratchcard" element={<ScratchcardPage />} />
        <Route path="*" element={<div className="text-center text-red-600 mt-10">Página não encontrada</div>} />
      </Routes>
    </div>
  )
}

export default App
