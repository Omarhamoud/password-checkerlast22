const crypto = require('crypto');
const zxcvbn = require('zxcvbn');

// helper: generate a strong password from a seed (keeps determinism-ish but randomizes)
function generateFromSeed(seed, length = 16, useSymbols = true) {
  const normalized = (seed || '').replace(/[^A-Za-z0-9]/g, '') || 'User';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  const pool = upper + lower + digits + (useSymbols ? symbols : '');
  // start with first 3 chars derived from seed when possible
  let pw = normalized.slice(0, 3);
  const rnd = crypto.randomBytes(Math.max(length - pw.length, 1));
  for (let i = 0; i < length - pw.length; i++) {
    pw += pool.charAt(rnd[i] % pool.length);
  }
  // ensure character class coverage
  if (!/[A-Z]/.test(pw)) pw = upper.charAt(rnd[0] % upper.length) + pw.slice(1);
  if (!/[a-z]/.test(pw)) pw = pw.slice(0,1) + lower.charAt(rnd[1] % lower.length) + pw.slice(2);
  if (!/[0-9]/.test(pw)) pw = pw.slice(0,2) + digits.charAt(rnd[2] % digits.length) + pw.slice(3);
  if (useSymbols && !/[!@#$%^&*()\-_=+\[\]{}<>?]/.test(pw)) pw = pw.slice(0,3) + symbols.charAt(rnd[3] % symbols.length) + pw.slice(4);
  return pw.slice(0, length);
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
    // treat as not pwned on API error (fail open for privacy; adjust if you prefer fail closed)
    return { pwned: false, count: 0 };
  }
  const text = await resp.text();
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);
  if (!hit) return { pwned: false, count: 0 };
  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count };
}

module.exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };

  try {
    const body = JSON.parse(event.body || '{}');
    const action = (body.action || 'test').toString();

    if (action === 'test') {
      const password = (body.password || '').toString();
      if (!password) return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };

      // compute zxcvbn and hibp in parallel
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
          strength_feedback: z.feedback,
          suggested_password: null,
          suggested_password_score: 0
        })
      };
    }

    if (action === 'suggest') {
      // seed comes from user-provided fields (name|birth) per frontend
      const seed = (body.seed || '').toString();
      const length = parseInt(body.length, 10) || 16;
      const symbols = !!body.symbols;
      if (!seed.trim()) return { statusCode: 400, body: JSON.stringify({ error: 'seed_required' }) };

      // Try several times to produce a non-pwned suggestion
      let suggestion = null;
      let suggestedScore = 0;
      for (let i = 0; i < 8; i++) {
        // mix seed with iteration to produce variety
        const cand = generateFromSeed(seed + '|' + i, length, symbols);
        const chk = await checkHIBP(cand).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestion = cand;
          suggestedScore = zxcvbn(cand).score;
          break;
        }
      }
      // fallback: random strong password
      if (!suggestion) {
        suggestion = generateFromSeed(seed + '|' + Math.random().toString(36), length, symbols);
        suggestedScore = zxcvbn(suggestion).score;
      }

      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          suggested_password: suggestion,
          suggested_password_score: suggestedScore
        })
      };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'unknown_action' }) };
  } catch (e) {
    console.error('Function error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
