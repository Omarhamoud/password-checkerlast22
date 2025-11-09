
const crypto = require('crypto');


const zxcvbn = require('zxcvbn');


function generateStrongPassword(length = 16) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  
 
  let pw = upper[Math.floor(Math.random() * upper.length)]
         + lower[Math.floor(Math.random() * lower.length)]
         + digits[Math.floor(Math.random() * digits.length)]
         + symbols[Math.floor(Math.random() * symbols.length)];
  
  const all = upper + lower + digits + symbols;
  for (let i = pw.length; i < length; i++) {
    pw += all[Math.floor(Math.random() * all.length)];
  }
  
 
  const arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]]; 
  }
  return arr.join('');
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
    console.error('HIBP API error');
    
    return { pwned: false, count: 0 };
  }

  
  const text = await resp.text();
  
  
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);

  if (!hit) {
    
    return { pwned: false, count: 0 };
  }


  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count: count };
}



exports.handler = async (event) => {
 
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  try {
    
    const body = JSON.parse(event.body || '{}');
    const { password, length } = body; 
    
    if (!password || typeof password !== 'string') {
      return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };
    }
    
    
    const pwLength = [12, 16, 20].includes(length) ? length : 16;

  
    const [z, hibp] = await Promise.all([
      zxcvbn(password),  
      checkHIBP(password) 
    ]);

    const strength_score = z.score; 

   
    let suggested = null;
    let suggestedScore = 0;
    
    if (strength_score < 4 || hibp.pwned) {
     
      for (let i = 0; i < 5; i++) {
        suggested = generateStrongPassword(pwLength); 
        const chk = await checkHIBP(suggested).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestedScore = zxcvbn(suggested).score;
          break; 
        }
      }
    }

   
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store' 
      },
      body: JSON.stringify({
        pwned: hibp.pwned,
        pwned_count: hibp.count,
        strength_score: strength_score,
        strength_feedback: z.feedback,
        suggested_password: suggested, 
        suggested_password_score: suggestedScore
      })
    };
  } catch (e) {
   
    console.error('Internal function error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
const crypto = require('crypto');


const zxcvbn = require('zxcvbn');


function generateStrongPassword(length = 16) {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}<>?';
  
 
  let pw = upper[Math.floor(Math.random() * upper.length)]
         + lower[Math.floor(Math.random() * lower.length)]
         + digits[Math.floor(Math.random() * digits.length)]
         + symbols[Math.floor(Math.random() * symbols.length)];
  
  const all = upper + lower + digits + symbols;
  for (let i = pw.length; i < length; i++) {
    pw += all[Math.floor(Math.random() * all.length)];
  }
  
 
  const arr = pw.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]]; 
  }
  return arr.join('');
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
    console.error('HIBP API error');
    
    return { pwned: false, count: 0 };
  }

  
  const text = await resp.text();
  
  
  const hit = text.split('\n').find(line => line.split(':')[0].toUpperCase() === suffix);

  if (!hit) {
    
    return { pwned: false, count: 0 };
  }


  const count = parseInt(hit.split(':')[1], 10) || 0;
  return { pwned: true, count: count };
}



exports.handler = async (event) => {
 
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'method_not_allowed' }) };
  }

  try {
    
    const body = JSON.parse(event.body || '{}');
    const { password, length } = body; 
    
    if (!password || typeof password !== 'string') {
      return { statusCode: 400, body: JSON.stringify({ error: 'password_required' }) };
    }
    
    
    const pwLength = [12, 16, 20].includes(length) ? length : 16;

  
    const [z, hibp] = await Promise.all([
      zxcvbn(password),  
      checkHIBP(password) 
    ]);

    const strength_score = z.score; 

   
    let suggested = null;
    let suggestedScore = 0;
    
    if (strength_score < 4 || hibp.pwned) {
     
      for (let i = 0; i < 5; i++) {
        suggested = generateStrongPassword(pwLength); 
        const chk = await checkHIBP(suggested).catch(() => ({ pwned: false }));
        if (!chk.pwned) {
          suggestedScore = zxcvbn(suggested).score;
          break; 
        }
      }
    }

   
    return {
      statusCode: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store' 
      },
      body: JSON.stringify({
        pwned: hibp.pwned,
        pwned_count: hibp.count,
        strength_score: strength_score,
        strength_feedback: z.feedback,
        suggested_password: suggested, 
        suggested_password_score: suggestedScore
      })
    };
  } catch (e) {
   
    console.error('Internal function error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'internal_error', details: e.message }) };
  }
};
