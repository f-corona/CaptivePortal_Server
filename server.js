require('dotenv').config()
const express = require('express')
const fetch = require('node-fetch')
const nodemailer = require('nodemailer')
const https = require('https')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

const SSI_SERVER = process.env.SSI_SERVICE_URL || 'http://192.168.0.102:3000'
const PORT = process.env.PORT || 3000
const OPNSENSE_URL = process.env.OPNSENSE_URL
const OPNSENSE_API_KEY = process.env.OPNSENSE_API_KEY
const OPNSENSE_API_SECRET = process.env.OPNSENSE_API_SECRET

const httpsAgent = new https.Agent({ rejectUnauthorized: false })

const issuedConnections = new Set()
const verifiedConnections = new Set()

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
})

const otpStore = {}

function generaOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

app.get('/', function(req, res) {
  res.sendFile(__dirname + '/public/index.html')
})

app.get('/login', function(req, res) {
  res.sendFile(__dirname + '/public/login.html')
})

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

app.post('/issue', async function(req, res) {
  const connectionId = req.body.connectionId
  const email = req.body.email

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
      res.json({ ok: false, message: 'Attesa connessione wallet...' })
    }
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message })
  }
})

app.post('/verify', async function(req, res) {
  const connectionId = req.body.connectionId
  const zone = '0'

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
      const credentials = Buffer.from(OPNSENSE_API_KEY + ':' + OPNSENSE_API_SECRET).toString('base64')

      const opnResponse = await fetch(OPNSENSE_URL + '/api/captiveportal/session/connect', {
        method: 'POST',
        agent: httpsAgent,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + credentials
        },
        body: JSON.stringify({ zoneid: zone, ip: clientIp })
      })
      const opnData = await opnResponse.json()
      console.log('Sblocco OPNsense per ' + clientIp + ':', opnData)

      verifiedConnections.add(connectionId)
      res.json({ ok: true })
    } else {
      res.json({ ok: false, message: 'Verifica in corso...' })
    }
  } catch (err) {
    console.error('Errore verifica:', err.message)
    res.status(500).json({ ok: false, message: err.message })
  }
})

app.post('/email/send', async function(req, res) {
  const email = req.body.email
  try {
    const otp = generaOTP()
    otpStore[email] = { otp: otp, createdAt: Date.now() }
    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Accesso Wi-Fi - Codice di verifica',
      text: 'Il tuo codice di verifica e\': ' + otp
    })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: 'Errore invio email' })
  }
})

app.post('/email/verify', async function(req, res) {
  const email = req.body.email
  const otp = req.body.otp
  const record = otpStore[email]

  if (!record || record.otp !== otp) {
    return res.json({ ok: false, message: 'Codice errato' })
  }

  delete otpStore[email]

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