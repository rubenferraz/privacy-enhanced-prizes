import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import confetti from 'canvas-confetti'
import { RSAKey, BigInteger } from 'jsbn'

// Helper to generate a random BigInteger in [1, n-1]
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

const API_URL = 'http://localhost:8000'
const SCRATCHCARD_API = `${API_URL}/scratchcard/ot/encrypted`
const RSA_API = `${API_URL}/crypto/rsa/public`
const OT_REVEAL_API = `${API_URL}/scratchcard/ot/reveal`

function pemToModExp(pem) {
  // Parse PEM to get modulus (n) and exponent (e)
  // This is a minimal parser for demo, assumes 2048-bit key and standard PEM
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '')
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  // ASN.1 parsing: skip header, find modulus and exponent
  // This is a hack for demo, for production use a real ASN.1 parser
  let i = 0
  while (i < der.length && der[i] !== 0x02) i++ // INTEGER tag
  i++
  let modLen = der[i]
  if (modLen & 0x80) {
    const nBytes = modLen & 0x7f
    modLen = 0
    for (let j = 0; j < nBytes; ++j) modLen = (modLen << 8) | der[i + 1 + j]
    i += nBytes
  }
  i++
  let modulus = der.slice(i, i + modLen)
  i += modLen
  while (i < der.length && der[i] !== 0x02) i++
  i++
  let expLen = der[i++]
  let exponent = der.slice(i, i + expLen)
  return {
    n: new BigInteger([...modulus].map(x => x.toString(16).padStart(2, '0')).join(''), 16),
    e: new BigInteger([...exponent].map(x => x.toString(16).padStart(2, '0')).join(''), 16)
  }
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

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!token) {
      navigate('/login')
    }
  }, [token, navigate])

  // Fetch encrypted scratchcards, claim status, and RSA public key
  useEffect(() => {
    async function fetchData() {
      setError('')
      try {
        const [encRes, rsaRes] = await Promise.all([
          fetch(SCRATCHCARD_API).then(r => r.json()),
          fetch(RSA_API).then(r => r.json())
        ])
        setEncryptedScratchcards(encRes.encrypted_scratchcards || [])
        setClaims(encRes.claims || [])
        setRsaPublicKey(rsaRes.rsa_public_key || '')
        // Fix: parse round_end as ISO string, handle trailing Z and possible double timezone
        if (encRes.round_end) {
          // Remove trailing 'Z' if already has a timezone offset
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

  // Timer countdown effect and reset selectedIndex when round changes
  useEffect(() => {
    if (!roundEnd) {
      setTimeLeft('')
      return
    }
    // Reset selectedIndex if roundEnd changed (new round)
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

  // Save local history to localStorage on change
  useEffect(() => {
    localStorage.setItem('scratchcard_history', JSON.stringify(localHistory))
  }, [localHistory])

  // Add CSS for scratch animation
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
        mask-image: linear-gradient(120deg, transparent 0%, black 30%, black 100%);
        -webkit-mask-image: linear-gradient(120deg, transparent 0%, black 30%, black 100%);
        animation: scratch-wipe 1s cubic-bezier(.7,0,.3,1) forwards;
      }
      @keyframes scratch-wipe {
        0% {
          mask-position: 100% 0;
          -webkit-mask-position: 100% 0;
          opacity: 1;
        }
        60% {
          opacity: 1;
        }
        100% {
          mask-position: 0 0;
          -webkit-mask-position: 0 0;
          opacity: 0;
        }
      }
      `
      document.head.appendChild(style)
    }
  }, [])

  // Show confetti when win (canvas-confetti)
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
      const res = await fetch(OT_REVEAL_API, {
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

  // Logout handler
  async function handleLogout() {
    if (!token) return
    try {
      await fetch('http://localhost:8000/auth/logout?token=' + encodeURIComponent(token))
    } catch {}
    localStorage.removeItem('token')
    setToken('')
    navigate('/login')
  }

  // Determine win/lose message for current round
  let winMsg = ''
  if (selectedIndex !== null && scratchcardResult) {
    if (scratchcardResult.trim() === '1') {
      winMsg = '🎉 Congratulations, you WON this round!'
    } else if (scratchcardResult.trim() === '0') {
      winMsg = '🙁 Sorry, not a winner this round.'
    } else {
      winMsg = `Result: ${scratchcardResult}`
    }
  } else if (selectedIndex !== null && claims[selectedIndex]?.claimed) {
    // If user already claimed, show last result
    const last = localHistory.find(
      h => h.roundEnd === (roundEnd ? roundEnd.toISOString() : null)
    )
    if (last) {
      if (last.value.trim() === '1') {
        winMsg = '🎉 Congratulations, you WON this round!'
      } else if (last.value.trim() === '0') {
        winMsg = '🙁 Sorry, not a winner this round.'
      } else {
        winMsg = `Result: ${last.value}`
      }
    }
  }

  // Determine if user already played this round
  const alreadyPlayed = (() => {
    if (!roundEnd) return false
    const thisRound = localHistory.find(
      h => h.roundEnd === (roundEnd ? roundEnd.toISOString() : null)
    )
    return !!thisRound
  })()

  return (
    <div className="container mx-auto mt-16 p-8 bg-zinc-900 rounded shadow">
      {/* Confetti handled by canvas-confetti, no JSX needed */}
      <div className="flex justify-between items-center mb-2">
        <h2 className="text-2xl font-extralight mb-3 text-zinc-100 tracking-wide uppercase">Scratchcard Page</h2>
      </div>
      <div className="mb-2 flex items-center justify-end gap-2">
        <span className="text-xs text-zinc-200 tracking-wide font-extralight">Next round in:</span>
        <span className="text-lg text-zinc-200 tracking-wide font-extralight">{timeLeft}</span>
      </div>
      <div className="mb-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        {encryptedScratchcards.map((_, idx) => {
          const claimed = claims[idx]?.claimed
          const selected = selectedIndex === idx
          const unavailable = claimed || loading || alreadyPlayed
          return (
            <button
              key={idx}
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
                  : 'linear-gradient(120deg, #f7e07c 0%, #f9d423 100%)'
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
              <span className="text-xs font-bold tracking-widest uppercase mb-1 z-10 relative">
                Scratchcard #{idx}
              </span>
              <span className={`text-md italic z-10 relative ${claimed ? 'line-through' : ''}`}>
                {claimed ? 'CLAIMED' : 'SCRATCH ME'}
              </span>
              {selected && !claimed && (
                <span className="mt-2 text-emerald-600 text-xs font-bold animate-pulse z-40 relative">Selected</span>
              )}
            </button>
          )
        })}
      </div>
      {winMsg && (
        <div className="mt-4 text-center">
          <span className={`text-lg font-bold ${winMsg.includes('WON') ? 'text-emerald-400' : 'text-red-400'}`}>
            {winMsg}
          </span>
        </div>
      )}
      {alreadyPlayed && (
        <div className="mt-2 text-center text-xs text-zinc-400">
          You have already played this round. Wait for the next round to play again.
        </div>
      )}
      {error && (
        <div className="mt-4 text-center text-red-400">{error}</div>
      )}
      <div className="mt-8 text-xs text-zinc-500 container text-clip">
        <div>RSA Public Key (PEM):</div>
        <p className="bg-zinc-800 p-2 rounded font-mono text-clip">
          {rsaPublicKey}
        </p>
      </div>
      {localHistory.length > 0 && (
        <div className="mt-8">
          <h3 className="text-xs text-zinc-400 mb-2 uppercase tracking-widest">Your Scratchcard History</h3>
          <ul className="text-xs text-zinc-300 space-y-1">
            {localHistory.slice(0, 10).map((h, i) => (
              <li key={i} className="flex items-center gap-2">
                <span className="font-mono">{h.date.slice(0, 19).replace('T', ' ')}</span>
                <span className="font-mono">|</span>
                <span>Round: {h.roundEnd ? h.roundEnd.slice(0, 19).replace('T', ' ') : '-'}</span>
                <span className="font-mono">|</span>
                <span>Card #{h.index}</span>
                <span className={`font-bold ${h.value.trim() === '1' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {h.value.trim() === '1' ? 'WIN' : h.value.trim() === '0' ? 'LOSE' : h.value}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default ScratchcardPage
