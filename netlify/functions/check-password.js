const crypto = require('crypto');
const zxcvbn = require('zxcvbn');

function generateFromSeed(seed, length = 16, useSymbols = true) {
  // seed is sent as `${name}|${birth}`
  const [rawName = '', rawBirth = ''] = String(seed || '').split('|');

  // Take letters from name (A–Z only). Fallback if empty.
  let nameLetters = rawName.replace(/[^A-Za-z]/g, '') || 'User';

  // Take digits from birth (year). Use last 2 digits; fallback "00" if missing.
  const birthDigits = rawBirth.replace(/\D/g, '');
  const year2 = (birthDigits.slice(-2) || '00');

  // Simple mix: first 2 letters of name + last 2 digits of year (4 chars total)
  // Example: Ahmad + 2001  =>  "Ah01"
  const tag = (nameLetters.slice(0, 2) + year2).padEnd(4, 'X');

  const upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower   = 'abcdefghijklmnopqrstuvwxyz';
  const digits  = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  const pool    = upper + lower + digits + (useSymbols ? symbols : '');

  // Start password with the simple tag (name+year), rest is random
  let pw = tag;

  // Fill the rest with real randomness
  const need = Math.max(length - pw.length, 0);
  const rnd  = crypto.randomBytes(Math.max(need, 4));
  for (let i = 0; i < need; i++) {
    pw += pool.charAt(rnd[i] % pool.length);
  }

  // Ensure character classes exist (keeps strong composition)
  if (!/[A-Z]/.test(pw)) pw = upper.charAt(rnd[0] % upper.length) + pw.slice(1);
  if (!/[a-z]/.test(pw)) pw = pw.slice(0,1) + lower.charAt(rnd[1] % lower.length) + pw.slice(2);
  if (!/[0-9]/.test(pw)) pw = pw.slice(0,2) + digits.charAt(rnd[2] % digits.length) + pw.slice(3);
  if (useSymbols && !/[!@#$%^&*()\-_=+\[\]{}<>?]/.test(pw))
    pw = pw.slice(0,3) + symbols.charAt(rnd[3] % symbols.length) + pw.slice(4);

  // Enforce exact length
  pw = pw.replace(/\s/g, '');
  while (pw.length < length) {
    const extra = crypto.randomBytes(1)[0];
    pw += pool.charAt(extra % pool.length);
  }
  if (pw.length > length) pw = pw.slice(0, length);

  return pw;
}

function sha1Hex(input) {
  return crypto.createHash('sha1').update(input, 'utf8').digest('hex').toUpperCase();
}

async function checkHIBP(password) {
  const sha1 = sha1Hex(password);
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'User-Agent': 'Graduation-Project-Password-Checker' }
  });
  if (!resp || !resp.ok) {
    return { pwned: false, count: 0 };
  }
  const text = await resp.text();
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);
  if (!hit) return { pwned: false, count: 0 };
  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count };
}

module.exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const action = (body.action || 'test').toString();

    if (action === 'test') {
      const password = (body.password || '').toString();
      if (!password) return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };

      const [z, hibp] = await Promise.all([
        zxcvbn(password),
        checkHIBP(password)
      ]);

      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          pwned: hibp.pwned,
          pwned_count: hibp.count,
          strength_score: z.score,
          strength_feedback: z.feedback
        })
      };
    }

    if (action === 'suggest') {
      const seed = (body.seed || '').toString();
      let length = parseInt(body.length, 10);
      const symbols = !!body.symbols;

      if (!seed.trim()) return { statusCode: 400, body: JSON.stringify({ error: 'seed_required' }) };
      if (!Number.isFinite(length)) length = 16;
      length = Math.max(8, Math.min(64, length));

      let suggestion = null;
      let suggestedScore = 0;

      for (let i = 0; i < 8; i++) {
        const cand = generateFromSeed(seed + '|' + i, length, symbols);
        const chk = await checkHIBP(cand).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestion = cand; // exact length already enforced
          suggestedScore = zxcvbn(cand).score;
          break;
        }
      }

      if (!suggestion) {
        suggestion = generateFromSeed(seed + '|' + Math.random().toString(36), length, symbols);
        suggestedScore = zxcvbn(suggestion).score;
      }

      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          requested_length: parseInt(body.length, 10),
          used_length: length,
          suggested_password: suggestion,
          suggested_password_score: suggestedScore
        })
      };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'unknown_action' }) };

  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
