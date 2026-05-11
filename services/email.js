const nodemailer = require('nodemailer')

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

async function sendOTP(email) {
  const otp = generaOTP()
  otpStore[email] = { otp, createdAt: Date.now() }
  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'Accesso Wi-Fi - Codice di verifica',
    text: 'Il tuo codice di verifica e\': ' + otp
  })
}

function verifyOTP(email, otp) {
  const record = otpStore[email]
  if (!record || record.otp !== otp) {
    return { ok: false, message: 'Codice errato' }
  }
  delete otpStore[email]
  return { ok: true }
}

module.exports = { sendOTP, verifyOTP }
