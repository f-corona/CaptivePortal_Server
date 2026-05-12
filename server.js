require('dotenv').config()
const express = require('express')
const fetch = require('node-fetch')
const { sendOTP, verifyOTP } = require('./services/email')
const { unlockIp } = require('./services/opnsense')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))
app.use('/images', express.static('images'))

const SSI_SERVER = process.env.SSI_SERVICE_URL || 'http://192.168.0.102:3000'
const PORT = process.env.PORT || 3000

//tiene traccia dei connectionId a cui e' gia' stata emessa una credenziale
const issuedConnections = new Set()
//tiene traccia dei connectionId gia' autenticati e sbloccati su OPNsense
const verifiedConnections = new Set()

app.get('/', function(req, res) {
  res.sendFile(__dirname + '/public/index.html')
})

app.get('/login', function(req, res) {
  res.sendFile(__dirname + '/public/login.html')
})

//chiede al server SSI un nuovo QR code da restituire al frontend
app.get('/connect', async function(req, res) {
  try {
    const response = await fetch(SSI_SERVER + '/ssi/connection/qrcode')
    const data = await response.json()
    res.json(data)
  } catch (err) {
    console.error('Errore SSI connect:', err.message)
    res.status(500).json({ error: 'Server SSI non raggiungibile' })
  }
})

//emette una credenziale SSI contenente l'email dell'utente
//la chiamata e' bloccante: il server SSI risponde solo quando BCWallet ha accettato
app.post('/issue', async function(req, res) {
  const { connectionId, email } = req.body

  if (issuedConnections.has(connectionId)) {
    return res.json({ ok: true })
  }

  try {
    const response = await fetch(SSI_SERVER + '/ssi/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        outOfBandId: connectionId,
        credential: [{ name: 'email', value: email }]
      })
    })
    const data = await response.json()
    if (data.ok) {
      issuedConnections.add(connectionId)
      res.json({ ok: true })
    } else {
      res.json({ ok: false, message: data.message || 'Emissione fallita' })
    }
  } catch (err) {
    console.error('Errore issue:', err.message)
    res.status(500).json({ ok: false, message: err.message })
  }
})

//verifica la proof request SSI e sblocca l'IP su OPNsense
//la chiamata e' bloccante: il server SSI risponde solo quando BCWallet ha risposto
app.post('/verify', async function(req, res) {
  const { connectionId } = req.body

  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
  const clientIp = rawIp.replace(/^::ffff:/, '').split(',')[0].trim()

  if (verifiedConnections.has(connectionId)) {
    return res.json({ ok: true })
  }

  try {
    const proofResponse = await fetch(SSI_SERVER + '/ssi/credentials/proof', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ outOfBandId: connectionId })
    })
    const proofData = await proofResponse.json()

    if (proofData.ok && proofData.receipt) {
      verifiedConnections.add(connectionId)
      const opnData = await unlockIp(clientIp)
      console.log('Sblocco OPNsense per ' + clientIp + ':', opnData)
      res.json({ ok: true })
    } else {
      res.json({ ok: false, message: proofData.message || 'Verifica fallita' })
    }
  } catch (err) {
    console.error('Errore verifica:', err.message)
    res.status(500).json({ ok: false, message: err.message })
  }
})

//invia un OTP via email
app.post('/email/send', async function(req, res) {
  try {
    await sendOTP(req.body.email)
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: 'Errore invio email' })
  }
})

//verifica OTP e restituisce un QR code SSI
app.post('/email/verify', async function(req, res) {
  const { email, otp } = req.body
  const result = verifyOTP(email, otp)
  if (!result.ok) {
    return res.json(result)
  }

  try {
    const response = await fetch(SSI_SERVER + '/ssi/connection/qrcode')
    const data = await response.json()
    res.json({ ok: true, connectionId: data.connectionId, qrCodeDataUrl: data.qrCodeDataUrl })
  } catch (err) {
    res.status(500).json({ error: 'Errore generazione QR' })
  }
})

app.listen(PORT, function() {
  console.log('CaptivePortal SSI App su porta ' + PORT)
})