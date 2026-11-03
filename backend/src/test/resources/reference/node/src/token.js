const crypto = require('crypto');

function legacyHash(text) {
  return crypto.createHash('md5').update(text).digest('hex');
}

function encrypt(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([cipher.update(text), cipher.final()]);
}

const agent = new https.Agent({ rejectUnauthorized: false });
module.exports = { legacyHash, encrypt, agent };
