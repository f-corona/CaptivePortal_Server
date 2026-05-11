const https = require('https')
const fetch = require('node-fetch')

const httpsAgent = new https.Agent({ rejectUnauthorized: false })

async function unlockIp(clientIp) {
  const credentials = Buffer.from(
    process.env.OPNSENSE_API_KEY + ':' + process.env.OPNSENSE_API_SECRET
  ).toString('base64')

  const response = await fetch(process.env.OPNSENSE_URL + '/api/captiveportal/session/connect', {
    method: 'POST',
    agent: httpsAgent,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + credentials
    },
    body: JSON.stringify({ zoneid: '0', ip: clientIp })
  })
  return response.json()
}

module.exports = { unlockIp }
