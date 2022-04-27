'use strict'

const crypto = require('crypto')
const https = require('https')

const cache = {} // (publicKey -> cert) cache

class SignatureValidationError extends Error {}

function convertX509CertToPEM (X509Cert) {
  const pemPreFix = '-----BEGIN CERTIFICATE-----\n'
  const pemPostFix = '-----END CERTIFICATE-----'

  const base64 = X509Cert
  const certBody = base64.match(/.{0,64}/g).join('\n')

  return pemPreFix + certBody + pemPostFix
}

async function getAppleCertificate (publicKeyUrl) {
  const url = new URL(publicKeyUrl)
  if (!url.host.endsWith('.apple.com')) {
    throw new SignatureValidationError('Invalid publicKeyUrl: host should be apple.com')
  }
  if (url.protocol !== 'https:') {
    throw new SignatureValidationError(
      'Invalid publicKeyUrl: should use https'
    )
  }

  const [error, base64Data, httpResp] = await new Promise((resolve) => {
    https.get(publicKeyUrl, (res) => {
      let data = ''
      if (res.statusCode !== 200) {
        return resolve([`HTTP status: ${res.statusCode}, expected 200.`])
      }
      res.on('error', (error) => resolve([error]))
        .on('data', (chunk) => (data += chunk.toString('base64')))
        .on('end', () => resolve([null, data, res]))
    })
  })

  if (error) {
    throw new SignatureValidationError(error)
  }

  const publicKey = convertX509CertToPEM(base64Data)

  return [publicKey, httpResp]
}

/* jslint bitwise:true */
function convertTimestampToBigEndian (timestamp) {
  // The timestamp parameter in Big-Endian UInt-64 format
  const buffer = Buffer.alloc(8)
  buffer.fill(0)

  const high = ~~(timestamp / 0xffffffff) // jshint ignore:line
  const low = timestamp % (0xffffffff + 0x1) // jshint ignore:line

  buffer.writeUInt32BE(parseInt(high, 10), 0)
  buffer.writeUInt32BE(parseInt(low, 10), 4)

  return buffer
}
/* jslint bitwise:false */

function verifySignature (publicKey, idToken) {
  const verifier = crypto.createVerify('sha256')
  verifier.update(idToken.playerId, 'utf8')
  verifier.update(idToken.bundleId, 'utf8')
  verifier.update(convertTimestampToBigEndian(idToken.timestamp))
  verifier.update(idToken.salt, 'base64')

  const valid = verifier.verify(publicKey, idToken.signature, 'base64')
  return valid
}

async function verify (idToken, useCaching = true) {
  const url = idToken.publicKeyUrl
  let publicKey = useCaching && cache[url]
  if (!publicKey) {
    let headers
    [publicKey, {headers}] = await getAppleCertificate(url)

    if (useCaching) {
      // if there's a cache-control header
      const maxAge = headers['cache-control']?.match(/max-age=([0-9]+)/)?.[1]
      const parsed = parseInt(maxAge, 10) * 1000
      // check parsed for falsy value, eg. null or zero
      if (parsed) {
        // if we got max-age
        cache[url] = publicKey // save in cache
        // we'll expire the cache entry later, as per max-age
        setTimeout(() => delete cache[url], parsed).unref()
      }
    }
  }

  return verifySignature(publicKey, idToken)
}

module.exports = {
  verify,
  verifySignature,
  SignatureValidationError,
  convertTimestampToBigEndian,
}
