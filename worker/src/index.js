// SECURITY CONFIG
const ALLOWED_ORIGINS = [
  'https://navi.buildn.cloud',
  'https://navi.geo-ed.tech',
  'https://navi-dash.buildn.cloud',  // Admin dashboard
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];

const RATE_LIMIT = {
  maxRequests: 5,      // Max signups per IP
  windowMinutes: 60,   // Time window (1 hour)
};

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: corsHeaders(allowedOrigin),
      });
    }

    // Validate Origin header (block requests without valid origin)
    if (!ALLOWED_ORIGINS.includes(origin)) {
      return jsonResponse({ error: 'Forbidden' }, 403, allowedOrigin);
    }

    // GET - Fetch all signups (for admin dashboard, protected by Zero Trust)
    if (request.method === 'GET') {
      return handleGetSignups(env.DB, allowedOrigin);
    }

    // Only accept POST for signups
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405, allowedOrigin);
    }

    // Validate Content-Type
    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.includes('application/json')) {
      return jsonResponse({ error: 'Invalid content type' }, 400, allowedOrigin);
    }

    try {
      const body = await request.json();
      const { firstName, lastName, email, website } = body; // 'website' is honeypot

      // HONEYPOT: If 'website' field is filled, it's a bot
      if (website) {
        // Pretend success to not alert the bot
        return jsonResponse({ success: true, message: 'Signup successful!' }, 201, allowedOrigin);
      }

      // Validate required fields
      if (!firstName || !email) {
        return jsonResponse({ error: 'First name and email are required' }, 400, allowedOrigin);
      }

      // Validate name lengths
      if (firstName.length < 1 || firstName.length > 50) {
        return jsonResponse({ error: 'First name must be 1-50 characters' }, 400, allowedOrigin);
      }

      // Validate last name length only if provided
      if (lastName && lastName.length > 50) {
        return jsonResponse({ error: 'Last name must be 50 characters or less' }, 400, allowedOrigin);
      }

      // Validate email format
      if (!isValidEmail(email)) {
        return jsonResponse({ error: 'Invalid email format' }, 400, allowedOrigin);
      }

      // Get client IP for rate limiting
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

      // Check rate limit
      const rateLimitResult = await checkRateLimit(env.DB, clientIP);
      if (!rateLimitResult.allowed) {
        return jsonResponse({
          error: `Too many signups. Please try again in ${rateLimitResult.retryAfter} minutes.`
        }, 429, allowedOrigin);
      }

      // Insert signup
      await env.DB.prepare(
        'INSERT INTO signups (first_name, last_name, email, ip_hash) VALUES (?, ?, ?, ?)'
      ).bind(
        sanitize(firstName),
        lastName ? sanitize(lastName) : null,
        email.toLowerCase().trim(),
        await hashIP(clientIP) // Store hashed IP for rate limiting
      ).run();

      // Get signup count
      const { results } = await env.DB.prepare('SELECT COUNT(*) as count FROM signups').all();
      const count = results[0].count;

      return jsonResponse({
        success: true,
        message: 'Signup successful!',
        position: count
      }, 201, allowedOrigin);

    } catch (error) {
      // Handle duplicate email
      if (error.message.includes('UNIQUE constraint failed') && error.message.includes('email')) {
        return jsonResponse({ error: 'Email already registered' }, 409, allowedOrigin);
      }

      console.error('Signup error:', error);
      return jsonResponse({ error: 'Something went wrong. Please try again.' }, 500, allowedOrigin);
    }
  },
};

// Fetch all signups for admin dashboard
async function handleGetSignups(db, origin) {
  try {
    const { results } = await db.prepare(
      'SELECT id, name, first_name, last_name, email, created_at FROM signups ORDER BY created_at DESC'
    ).all();

    return jsonResponse({
      success: true,
      count: results.length,
      signups: results
    }, 200, origin);
  } catch (error) {
    console.error('Error fetching signups:', error);
    return jsonResponse({ error: 'Failed to fetch signups' }, 500, origin);
  }
}

// Rate limiting using D1
async function checkRateLimit(db, ip) {
  const ipHash = await hashIP(ip);
  const windowStart = new Date(Date.now() - RATE_LIMIT.windowMinutes * 60 * 1000).toISOString();

  const { results } = await db.prepare(
    'SELECT COUNT(*) as count FROM signups WHERE ip_hash = ? AND created_at > ?'
  ).bind(ipHash, windowStart).all();

  const requestCount = results[0].count;

  if (requestCount >= RATE_LIMIT.maxRequests) {
    return {
      allowed: false,
      retryAfter: RATE_LIMIT.windowMinutes
    };
  }

  return { allowed: true };
}

// Hash IP for privacy (don't store raw IPs)
async function hashIP(ip) {
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + 'navi-salt-2024'); // Add salt
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
}

// Sanitize input to prevent XSS
function sanitize(str) {
  return str.replace(/[<>]/g, '').trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': origin,
    },
  });
}
