import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import confetti from 'canvas-confetti'
import { RSAKey, BigInteger } from 'jsbn'
import { fetchWithMAC } from '../utils/mac'

// fun: generate a big integer
function randomBigInt(n) {
  // n: BigInteger
  const bytes = Math.ceil(n.bitLength() / 8)
  let r
  do {
    // Use crypto.getRandomValues for secure random
    const arr = new Uint8Array(bytes)
    window.crypto.getRandomValues(arr)
    let hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
    r = new BigInteger(hex, 16)
  } while (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE))
  return r
}


const API_URL = 'https://localhost:8000' 
const SCRATCHCARD_API = `${API_URL}/scratchcard/ot/encrypted`
const RSA_API = `${API_URL}/crypto/rsa/public`
const OT_REVEAL_API = `${API_URL}/scratchcard/ot/reveal`
const VERIFY_TOKEN_API = `${API_URL}/auth/verify-token`
const RENEW_TOKEN_API = `${API_URL}/auth/renew-token`

function pemToModExp(pem) {
  // pem to der
  const pemContents = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
  const binaryDer = atob(pemContents);
  const der = new Uint8Array(binaryDer.length);
  for (let i = 0; i < binaryDer.length; i++) {
    der[i] = binaryDer.charCodeAt(i);
  }
  
  // Parse ASN.1 DER format for RSA public key
  // SEQUENCE
  let pos = 0;
  if (der[pos++] !== 0x30) throw new Error('Expected SEQUENCE');
  
  // Skip sequence length
  let seqLen = der[pos++];
  if (seqLen & 0x80) {
    const lenBytes = seqLen & 0x7F;
    seqLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      seqLen = (seqLen << 8) | der[pos++];
    }
  }
  
  // skipping the algorithm identifier
  if (der[pos] !== 0x30) throw new Error('Expected AlgorithmIdentifier SEQUENCE');
  
  // start of BIT STRING
  const algoIdSeq = der[pos++];
  let algoIdLen = der[pos++];
  if (algoIdLen & 0x80) {
    const lenBytes = algoIdLen & 0x7F;
    algoIdLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      algoIdLen = (algoIdLen << 8) | der[pos++];
    }
  }
  pos += algoIdLen; // skipping the algorithm identifier
  
  // BIT STRING (which has the key)
  if (der[pos++] !== 0x03) throw new Error('Expected BIT STRING');
  
  // BIT STRING length
  let bitStringLen = der[pos++];
  if (bitStringLen & 0x80) {
    const lenBytes = bitStringLen & 0x7F;
    bitStringLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      bitStringLen = (bitStringLen << 8) | der[pos++];
    }
  }
  
  // skipping unused bits
  pos++;
  
  // Parsing the RSA pk structure
  if (der[pos++] !== 0x30) throw new Error('Expected SEQUENCE for RSA key');
  
  // skipping the sequence length
  let keySeqLen = der[pos++];
  if (keySeqLen & 0x80) {
    const lenBytes = keySeqLen & 0x7F;
    keySeqLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      keySeqLen = (keySeqLen << 8) | der[pos++];
    }
  }
  
  // INTEGER (mod)
  if (der[pos++] !== 0x02) throw new Error('Expected INTEGER for modulus');
  
  // get mod length
  let modLen = der[pos++];
  if (modLen & 0x80) {
    const lenBytes = modLen & 0x7F;
    modLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      modLen = (modLen << 8) | der[pos++];
    }
  }
  
  // skipping the leading 0 if present
  if (der[pos] === 0) {
    pos++;
    modLen--;
  }
  
  // extract mod
  const modulus = der.slice(pos, pos + modLen);
  pos += modLen;
  
  // INTEGER (exp)
  if (der[pos++] !== 0x02) throw new Error('Expected INTEGER for exponent');
  
  // get the exp length
  let expLen = der[pos++];
  if (expLen & 0x80) {
    const lenBytes = expLen & 0x7F;
    expLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      expLen = (expLen << 8) | der[pos++];
    }
  }
  
  // extract the exp value
  const exponent = der.slice(pos, pos + expLen);
  
  // converting to BigInteger
  return {
    n: new BigInteger([...modulus].map(x => x.toString(16).padStart(2, '0')).join(''), 16),
    e: new BigInteger([...exponent].map(x => x.toString(16).padStart(2, '0')).join(''), 16)
  };
}

function hexToBase64(hex) {
  return btoa(hex.match(/\w{2}/g).map(a => String.fromCharCode(parseInt(a, 16))).join(''))
}

function base64ToHex(b64) {
  return Array.from(atob(b64)).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

function ScratchcardPage() {
  const [encryptedScratchcards, setEncryptedScratchcards] = useState([])
  const [claims, setClaims] = useState([])
  const [rsaPublicKey, setRsaPublicKey] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(null)
  const [scratchcardResult, setScratchcardResult] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [token, setToken] = useState(() => localStorage.getItem('token') || '')
  const [roundEnd, setRoundEnd] = useState(null)
  const [timeLeft, setTimeLeft] = useState('')
  const [prevRoundEnd, setPrevRoundEnd] = useState(null)
  const [localHistory, setLocalHistory] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('scratchcard_history') || '[]')
    } catch {
      return []
    }
  })
  const [showConfetti, setShowConfetti] = useState(false)
  const confettiFiredRef = useRef(false)
  const [tokenExpiresIn, setTokenExpiresIn] = useState(null)

  const navigate = useNavigate()

  // Save token from login page if available
  useEffect(() => {
    // Listen for token changes in localStorage (e.g., after login)
    function syncToken() {
      setToken(localStorage.getItem('token') || '')
    }
    window.addEventListener('storage', syncToken)
    syncToken()
    return () => window.removeEventListener('storage', syncToken)
  }, [])

  // Função para renovar o token
  const renewToken = async () => {
    if (!token) return;
    
    try {
      setLoading(true);
      const response = await fetchWithMAC(RENEW_TOKEN_API, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Falha ao renovar token');
      }
      
      const data = await response.json();
      const newToken = data.token;
      
      // Atualizar o token no localStorage e no estado
      localStorage.setItem('token', newToken);
      setToken(newToken);
      
      // Resetar o erro se existir
      setError('');
      
      // Atualizar o tempo de expiração
      verifyToken();
      
    } catch (err) {
      console.error('Erro ao renovar token:', err);
      setError(`Erro ao renovar sessão: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };
  
  // Verificar validade do token periodicamente
  useEffect(() => {
    if (!token) return;

    // Função para verificar o token
    async function verifyToken() {
      try {
        const response = await fetchWithMAC(VERIFY_TOKEN_API, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        const data = await response.json();
        
        if (!data.valid) {
          // Token inválido - redirecionar para login
          console.warn('Token inválido:', data.reason);
          localStorage.removeItem('token');
          setToken('');
          navigate('/login', { replace: true });
          return;
        }
        
        // Atualizar tempo de expiração
        setTokenExpiresIn(data.remaining_time);
      } catch (err) {
        console.error('Erro ao verificar token:', err);
      }
    }

    // Verificar token imediatamente e depois a cada minuto
    verifyToken();
    const interval = setInterval(verifyToken, 60000);
    
    return () => clearInterval(interval);
  }, [token, navigate])

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!token) {
      navigate('/login')
    }
  }, [token, navigate])

  // obter as raspadinhas, o estado delas (claim ou não) e a chave RSA
  useEffect(() => {
    async function fetchData() {
      setError('')
      try {
        const [encRes, rsaRes] = await Promise.all([
          fetchWithMAC(SCRATCHCARD_API).then(r => r.json()),
          fetchWithMAC(RSA_API).then(r => r.json())
        ])
        setEncryptedScratchcards(encRes.encrypted_scratchcards || [])
        setClaims(encRes.claims || [])
        setRsaPublicKey(rsaRes.rsa_public_key || '')

        // tempo de fim da ronda
        if (encRes.round_end) {
          let roundEndStr = encRes.round_end
          if (roundEndStr.match(/\+\d{2}:\d{2}Z$/)) {
            roundEndStr = roundEndStr.replace(/Z$/, '')
          }
          const parsed = Date.parse(roundEndStr)
          if (!isNaN(parsed)) {
            setRoundEnd(new Date(parsed))
          } else {
            setRoundEnd(new Date(Date.now() + 60 * 60 * 1000))
          }
        } else {
          setRoundEnd(new Date(Date.now() + 60 * 60 * 1000))
        }
      } catch (err) {
        setError('Failed to fetch scratchcards or RSA key')
      }
    }
    fetchData()
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [])

  // temporizador
  useEffect(() => {
    if (!roundEnd) {
      setTimeLeft('')
      return
    }
    if (prevRoundEnd && roundEnd.getTime() !== prevRoundEnd.getTime()) {
      setSelectedIndex(null)
      setScratchcardResult('')
    }
    setPrevRoundEnd(roundEnd)

    const update = () => {
      const now = new Date()
      let diff = Math.floor((roundEnd.getTime() - now.getTime()) / 1000)
      if (isNaN(diff) || diff < 0) diff = 0
      const min = Math.floor(diff / 60)
      const sec = diff % 60
      setTimeLeft(`${min}:${sec.toString().padStart(2, '0')}`)
    }
    update()
    const timer = setInterval(update, 1000)
    return () => clearInterval(timer)
  }, [roundEnd, prevRoundEnd])

  // guardar o histórico localmente
  useEffect(() => {
    localStorage.setItem('scratchcard_history', JSON.stringify(localHistory))
  }, [localHistory])


  useEffect(() => {
    const styleId = 'scratchcard-anim-style'
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style')
      style.id = styleId
      style.innerHTML = `
      .scratch-anim-overlay {
        pointer-events: none;
        position: absolute;
        inset: 0;
        z-index: 10;
        background: repeating-linear-gradient(120deg, #f7e07c 0 10px, #f9d423 10px 20px);
        clip-path: polygon(0 0, 100% 0, 100% 100%, 0% 100%);
        animation: scratch-wipe 1s cubic-bezier(.7,0,.3,1) forwards;
      }
      @keyframes scratch-wipe {
        0% {
          clip-path: polygon(0 0, 100% 0, 100% 100%, 0% 100%);
          opacity: 1;
        }
        30% {
          clip-path: polygon(30% 0, 100% 0, 100% 100%, 0% 100%);
          opacity: 1;
        }
        60% {
          clip-path: polygon(60% 0, 100% 0, 100% 100%, 30% 100%);
          opacity: 0.9;
        }
        100% {
          clip-path: polygon(120% 0, 120% 0, 120% 100%, 100% 100%);
          opacity: 0;
        }
      }
      `
      document.head.appendChild(style)
    }
  }, [])

  // CONFETTI!
  useEffect(() => {
    if (scratchcardResult && scratchcardResult.trim() === '1' && !confettiFiredRef.current) {
      confettiFiredRef.current = true
      confetti({
        particleCount: 180,
        spread: 90,
        origin: { y: 0.6 },
        zIndex: 1000,
        colors: ['#f9d423', '#f7e07c', '#34d399', '#f87171']
      })
      setTimeout(() => { confettiFiredRef.current = false }, 2000)
    }
  }, [scratchcardResult])

  async function handleClaimScratchcard(idx) {
    setLoading(true)
    setScratchcardResult('')
    setError('')
    try {
      if (!token) {
        setError('You must be logged in to claim a scratchcard.')
        setLoading(false)
        return
      }
      if (idx === null || idx < 0 || idx >= encryptedScratchcards.length) {
        setError('Select a valid scratchcard')
        setLoading(false)
        return
      }
      if (claims[idx]?.claimed) {
        setError('Scratchcard already claimed')
        setLoading(false)
        return
      }
      const { n, e } = pemToModExp(rsaPublicKey)
      const ciphertextHex = base64ToHex(encryptedScratchcards[idx])
      const c = new BigInteger(ciphertextHex, 16)
      const r = randomBigInt(n)
      const re = r.modPow(e, n)
      const blinded = c.multiply(re).mod(n)
      const blindedHex = blinded.toString(16)
      const blindedB64 = hexToBase64(blindedHex)
      const res = await fetchWithMAC(OT_REVEAL_API, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ blinded_value: blindedB64, index: idx })
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.detail || 'Failed to reveal scratchcard')
        setLoading(false)
        return
      }
      const revealedHex = base64ToHex(data.revealed)
      const revealed = new BigInteger(revealedHex, 16)
      const rInv = r.modInverse(n)
      const m = revealed.multiply(rInv).mod(n)
      let result
      try {
        let hex = m.toString(16)
        if (hex.length % 2) hex = '0' + hex
        const bytes = hex.match(/.{1,2}/g).map(b => parseInt(b, 16))
        result = String.fromCharCode(...bytes).replace(/[^\x00-\x7F]/g, '')
        if (!result.trim()) result = m.toString()
      } catch {
        result = m.toString()
      }
      setScratchcardResult(result)
      setSelectedIndex(idx)
      // Save to local history
      setLocalHistory(h => [
        {
          roundEnd: roundEnd ? roundEnd.toISOString() : null,
          index: idx,
          value: result,
          date: new Date().toISOString()
        },
        ...h
      ])
    } catch (err) {
      setError('OT protocol failed: ' + err.message)
    }
    setLoading(false)
  }

  // Load the selected index and result from local history for current round
  useEffect(() => {
    if (roundEnd && localHistory.length > 0) {
      const currentRoundString = roundEnd.toISOString();
      const currentRoundPlay = localHistory.find(h => h.roundEnd === currentRoundString);
      
      if (currentRoundPlay) {
        setSelectedIndex(currentRoundPlay.index);
        setScratchcardResult(currentRoundPlay.value);
      }
    }
  }, [roundEnd, localHistory]);

  // Determine win/lose message for current round
  let winMsg = ''
  if (selectedIndex !== null && scratchcardResult) {
    if (scratchcardResult.trim() === '1') {
      winMsg = 'Parabéns, GANHOU!'
    } else if (scratchcardResult.trim() === '0') {
      winMsg = 'Não ganhou nada, mais sorte para a próxima!'
    } 
    // else {
    //   winMsg = `Resultado: ${scratchcardResult}`
    // }
  } 

  // verificar se o user já jogou nesta ronda
  const alreadyPlayed = (() => {
    if (!roundEnd) return false
    const thisRound = localHistory.find(
      h => h.roundEnd === (roundEnd ? roundEnd.toISOString() : null)
    )
    return !!thisRound
  })()

  // Add logout handler
  const handleLogout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await fetchWithMAC(`${API_URL}/auth/logout`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        localStorage.removeItem('token');
        localStorage.removeItem('scratchcard_history');
        navigate('/', { replace: true });
      }
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  return (
    <div className='flex flex-col items-center justify-center min-h-screen py-12'>
      <div className="container max-w-6xl p-8 bg-zinc-900 rounded shadow">
        <div className="flex justify-between items-center mb-2">
            <h2 className="text-2xl font-extralight mb-0 text-zinc-100 tracking-wide uppercase">Raspadinhas</h2>
            <div className="flex items-center gap-4">
              <div className="flex items-center justify-end gap-2">
                <span className="text-xs text-zinc-200 tracking-wide font-extralight">Tempo restante:</span>
                <span className="text-lg text-zinc-200 tracking-wide font-extralight">{timeLeft}</span>
              </div>
              {/* Add logout button */}
              <button
                onClick={handleLogout}
                className="bg-zinc-700 hover:bg-zinc-600 text-zinc-300 px-3 py-1 text-xs transition-colors"
              >
                Sair
              </button>
            </div>
          </div>
        <div className='grid grid-cols-1 md:grid-cols-3 gap-6'>

        <div className='col-span-1 md:col-span-2'>

          {/* Token expiration warning */}
          {tokenExpiresIn !== null && tokenExpiresIn < 300 && tokenExpiresIn > 0 && (
            <div className="mb-4 p-2 bg-amber-900/30 border border-amber-800 rounded-md text-center">
              <p className="text-amber-300 text-xs">
                ⚠️ A sua sessão expira em {Math.ceil(tokenExpiresIn / 60)} minuto(s).
                <button 
                  onClick={renewToken}
                  disabled={loading}
                  className="ml-2 px-2 py-0.5 bg-amber-700 hover:bg-amber-600 rounded text-amber-100 text-xs transition-colors"
                >
                  {loading ? 'Renovando...' : 'Renovar sessão'}
                </button>
              </p>
            </div>
          )}
          
          <div className="mb-4 grid grid-cols-2 md:grid-cols-5 gap-4">
            {encryptedScratchcards.map((_, idx) => {
              const claimed = claims[idx]?.claimed
              const selected = selectedIndex === idx
              const unavailable = claimed || loading || alreadyPlayed
              return (
                <button
                  key={idx}
                  data-idx={idx}
                  className={`
                    relative flex flex-col items-center justify-center
                    w-auto h-24 rounded-xl shadow-lg border-2
                    transition-all duration-200
                    overflow-hidden
                    ${claimed
                      ? 'bg-gradient-to-br from-zinc-500 to-zinc-700 border-zinc-400 text-zinc-300 cursor-not-allowed opacity-60'
                      : 'border-yellow-300'}
                    ${unavailable ? 'cursor-not-allowed hover:scale-100' : 'hover:scale-105 hover:shadow-2xl'}
                  `}
                  disabled={unavailable}
                  onClick={() => handleClaimScratchcard(idx)}
                  style={{
                    backgroundImage: claimed
                      ? 'repeating-linear-gradient(135deg, #888 0 10px, #aaa 10px 20px)'
                      : (() => {
                          if (roundEnd && selected && scratchcardResult) {
                            const isWinner = scratchcardResult.trim() === '1';
                            return isWinner ? 
                              'linear-gradient(120deg, #10b981 0%, #34d399 100%)' : 
                              'linear-gradient(120deg, #ef4444 0%, #f87171 100%)';
                          }
                          return 'linear-gradient(120deg, #f7e07c 0%, #f9d423 100%)';
                        })()
                  }}
                >
                  {/* Gray underlay for scratch effect */}
                  {!claimed && (
                    <div
                      className="absolute inset-0 z-0"
                      style={{
                        background: 'repeating-linear-gradient(135deg, #888 0 10px, #aaa 10px 20px)',
                        opacity: selected && !claimed ? 1 : 0,
                        transition: 'opacity 0.2s'
                      }}
                    />
                  )}
                  
                  {/* Decorative pattern for scratchcard */}
                  {!claimed && (
                    <div 
                      className="absolute inset-0 z-10 mix-blend-overlay opacity-60"
                      style={{
                        backgroundImage: `
                          radial-gradient(circle at 25% 25%, rgba(255,255,255,0.2) 2px, transparent 0),
                          radial-gradient(circle at 75% 75%, rgba(255,255,255,0.2) 2px, transparent 0),
                          radial-gradient(circle at 50% 50%, rgba(255,255,255,0.3) 3px, transparent 0),
                          radial-gradient(circle at 15% 85%, rgba(0,0,0,0.1) 2px, transparent 0),
                          radial-gradient(circle at 85% 15%, rgba(0,0,0,0.1) 2px, transparent 0)
                        `,
                        backgroundSize: '20px 20px, 20px 20px, 20px 20px, 20px 20px, 20px 20px',
                        backgroundPosition: '0 0, 0 0, 0 0, 0 0, 0 0',
                        pointerEvents: 'none'
                      }}
                    />
                  )}
                  
                  {/* Scratch mask animation */}
                  <AnimatePresence>
                    {selected && !claimed && (
                      <motion.div
                        key="scratch-mask"
                        initial={{ x: 0 }}
                        animate={{ x: '110%' }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 1.1, ease: [0.7, 0, 0.3, 1] }}
                        className="absolute inset-0 z-30 pointer-events-none"
                        style={{
                          background: 'linear-gradient(120deg, #f7e07c 0%, #f9d423 100%)',
                          boxShadow: '0 0 16px 4px #f9d42355',
                          borderRadius: 'inherit',
                        }}
                      />
                    )}
                  </AnimatePresence>
                  {/* Card content (always on top of gray underlay, under mask) */}
                    {/* <span className="text-xs font-bold tracking-widest uppercase mb-1 z-10 relative">
                    Scratchcard #{idx}
                  </span> */}
                  {/* <span className={`text-md italic z-10 relative ${claimed ? 'line-through' : ''}`}>
                    {claimed ? 'CLAIMED' : 'SCRATCH ME'}
                  </span> */}
                  
                  {/* Show a lottery/scratch symbol on unclaimed cards */}
                  {!claimed && !selected && (
                    <div className="text-zinc-800 font-bold z-20 relative">
                      <span className="text-3xl">€</span>
                    </div>
                  )}
                  
                  {/* Show result on selected card after revealing */}
                  {(() => {
                    // Only show for the current selection
                    if (selected && !claimed && scratchcardResult) {
                      return (
                        <div className="z-40 relative">
                          <span className="text-4xl font-bold text-white">
                            {scratchcardResult.trim() === '1' ? '€' : 'X'}
                          </span>
                        </div>
                      );
                    }
                    return null;
                  })()}
                  
                  {/* Show 'Selected' text only for actively selected card */}
                  {/* {selected && !claimed && (
                    <span className="mt-2 text-emerald-600 text-xs font-bold animate-pulse z-40 relative">Selected</span>
                  )} */}
                </button>
              )
            })}
          </div>
          {winMsg && (
            <div className="mt-4 text-center">
              <span className={`text-lg font-bold ${winMsg.includes('GANHOU') ? 'text-emerald-400' : 'text-red-400'}`}>
                {winMsg}
              </span>
            </div>
          )}
          {alreadyPlayed && (
            <div className="mt-2 text-center text-xs text-zinc-400">
              Já jogou nesta ronda. Espere pela próxima para jogar novamente!
            </div>
          )}
          {/* {error && (
            <div className="mt-4 text-center text-red-400">{error}</div>
          )} */}
          {(!token || !rsaPublicKey) && (
            <div className="mt-4 p-3 bg-red-900/30 border border-red-800 rounded-md">
              <p className="text-red-300 font-medium">
                <span className="text-red-200 font-bold">⚠️ Erro de Segurança</span>
              </p>
              <p className="text-red-400 text-sm mt-1">
                {!token ? (
                  <>
                    Não foi possível verificar a sua identidade. Por favor, faça login novamente.
                  </>
                ) : !rsaPublicKey ? (
                  <>
                    De momento não é possível garantir a confidencialidade e privacidade das suas jogadas.
                    Por favor, tente novamente mais tarde.
                  </>
                ) : (
                  <>
                    Ocorreu um erro de segurança. Por favor, recarregue a página ou contacte o suporte.
                  </>
                )}
              </p>
            </div>
          )}
          {/* <div className="mt-8 text-xs text-zinc-500 container text-clip">
            <div>RSA Public Key (PEM):</div>
            <p className="bg-zinc-800 p-2 rounded font-mono text-clip">
              {rsaPublicKey}
            </p>
          </div> */}

          </div>

         {localHistory.length > 0 && (
            <div className="">
              <h3 className="text-xs text-zinc-400 mb-2 uppercase tracking-widest">Histórico</h3>
              <ul className="text-xs text-zinc-300 space-y-1">
                {localHistory.slice(0, 10).map((h, i) => (
                  <li key={i} className="flex items-center gap-2">
                    {/* <span className="font-mono">{h.date.slice(0, 19).replace('T', ' ')}</span>
                    <span className="font-mono">|</span> */}
                    <span className="font-mono">Ronda: {h.roundEnd ? h.roundEnd.slice(0, 19).replace('T', ' ') : '-'}</span>
                    <span className="font-mono">|</span>
                    <span className={`font-bold ${h.value.trim() === '1' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {h.value.trim() === '1' ? 'VITÓRIA' : h.value.trim() === '0' ? 'DERROTA' : h.value}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          </div>
    </div>
    </div>
  )
}

export default ScratchcardPage
