require('dotenv').config()
const express = require('express')
const fetch = require('node-fetch')
const nodemailer = require('nodemailer')
const https = require('https')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public')) //serve i file statici dalla cartella public

//indirizzi e credenziali letti dal .env
const SSI_SERVER = process.env.SSI_SERVICE_URL || 'http://192.168.0.102:3000'
const PORT = process.env.PORT || 3000
const OPNSENSE_URL = process.env.OPNSENSE_URL
const OPNSENSE_API_KEY = process.env.OPNSENSE_API_KEY
const OPNSENSE_API_SECRET = process.env.OPNSENSE_API_SECRET

//agente HTTPS che ignora i certificati autofirmati (necessario per OPNsense in locale)
const httpsAgent = new https.Agent({ rejectUnauthorized: false })

//tiene traccia dei connectionId a cui e' gia' stata emessa una credenziale
const issuedConnections = new Set()
//tiene traccia dei connectionId gia' autenticati e sbloccati su OPNsense
const verifiedConnections = new Set()

//configura nodemailer per l'invio di email tramite Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
})

//dizionario temporaneo email -> { otp, createdAt }
const otpStore = {}

//genera un codice OTP numerico a 6 cifre
function generaOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

//homepage
app.get('/', function(req, res) {
  res.sendFile(__dirname + '/public/index.html')
})

//login page
app.get('/login', function(req, res) {
  res.sendFile(__dirname + '/public/login.html')
})

//chiede al server SSI un nuovo QR code da restituire al frontend
//il frontend lo mostra per farlo scansionare con BCWallet
app.get('/connect', async function(req, res) {
  try {
    const response = await fetch(SSI_SERVER + '/ssi/connection/qrcode')
    const data = await response.json()
    res.json(data) //restituisce connectionId e qrCodeDataUrl
  } catch (err) {
    console.error('Errore SSI connect:', err.message)
    res.status(500).json({ error: 'Server SSI non raggiungibile' })
  }
})

//emette una credenziale contenente l'email dell'utente
//viene chiamato dopo che l'utente ha scansionato il QR con BCWallet
app.post('/issue', async function(req, res) {
  const connectionId = req.body.connectionId
  const email = req.body.email

  //se la credenziale e' gia' stata emessa per questa connessione, non fare nulla
  if (issuedConnections.has(connectionId)) {
    return res.json({ ok: true })
  }

  try {
    //chiede al server SSI di emettere la credenziale con l'email come attributo
    const response = await fetch(SSI_SERVER + '/ssi/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        outOfBandId: connectionId,
        credential: [{ name: 'email', value: email }]
      })
    })
    const data = await response.json()
    if (data.ok) { //BCWallet ha accettato, salva il connectionId
      issuedConnections.add(connectionId)
      res.json({ ok: true })
    } else { //BCWallet non ha ancora accettato, il frontend riprova
      res.json({ ok: false, message: 'Attesa connessione wallet...' })
    }
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message })
  }
})

//verifica se l'utente ha accettato la proof request su BCWallet
//se sì, sblocca il suo IP su OPNsense tramite API REST
//viene chiamato in polling dal frontend finche' non ottiene ok: true
app.post('/verify', async function(req, res) {
  const connectionId = req.body.connectionId
  const zone = '0' //zona captive portal su OPNsense

  //ricava l'IP del client dalla richiesta
  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''
  const clientIp = rawIp.replace(/^::ffff:/, '').split(',')[0].trim()

  //se il client e' gia' stato verificato e sbloccato, non fare nulla
  if (verifiedConnections.has(connectionId)) {
    return res.json({ ok: true })
  }

  try {
    //manda una proof request al server SSI, che la inoltra a BCWallet
    const proofResponse = await fetch(SSI_SERVER + '/ssi/credentials/proof', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ outOfBandId: connectionId })
    })
    const proofData = await proofResponse.json()

    //se la proof e' stata accettata, il receipt contiene il JWT
    if (proofData.ok && proofData.receipt) {
      //costruisce le credenziali API di OPNsense in formato Base64 per Basic Auth
      const credentials = Buffer.from(OPNSENSE_API_KEY + ':' + OPNSENSE_API_SECRET).toString('base64')

      //chiama OPNsense per sbloccare l'IP del client nella zona captive portal
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

      //salva il connectionId come verificato per evitare sblocchi doppi
      verifiedConnections.add(connectionId)
      res.json({ ok: true })
    } else {
      //BCWallet non ha ancora risposto, il frontend riprovera'
      res.json({ ok: false, message: 'Verifica in corso...' })
    }
  } catch (err) {
    console.error('Errore verifica:', err.message)
    res.status(500).json({ ok: false, message: err.message })
  }
})

//genera e invia un OTP via email all'utente
//viene chiamato quando l'utente inserisce la sua email nel captive portal
app.post('/email/send', async function(req, res) {
  const email = req.body.email
  try {
    const otp = generaOTP()
    //salva l'OTP in memoria associato all'email, con timestamp
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

//verifica il codice OTP inserito dall'utente
//se corretto, genera un QR code SSI e lo restituisce al frontend
app.post('/email/verify', async function(req, res) {
  const email = req.body.email
  const otp = req.body.otp
  const record = otpStore[email]

  //controlla che l'OTP esista e corrisponda a quello inserito
  if (!record || record.otp !== otp) {
    return res.json({ ok: false, message: 'Codice errato' })
  }

  //OTP corretto: eliminalo dallo store per non poterlo riusare
  delete otpStore[email]

  try {
    //genera un nuovo QR code SSI da mostrare all'utente per la scansione
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