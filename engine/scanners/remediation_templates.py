"""
VibeCrack Engine - Vibe-Coder Remediation Templates

Provides copy-paste ready code snippets for fixing vulnerabilities,
organized by framework/stack. Instead of just saying "fix XSS",
this gives the developer the actual code to implement.
"""

# ============================================================
# SECURITY HEADERS - Code to add per framework
# ============================================================

HEADERS_NEXTJS = """
// next.config.ts - Add security headers
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://*.firebaseio.com https://*.googleapis.com;"
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains'
          },
        ],
      },
    ];
  },
};
export default nextConfig;
""".strip()

HEADERS_EXPRESS = """
// Express.js - Install and configure helmet
// npm install helmet

const helmet = require('helmet');
const app = express();

app.use(helmet());

// Or configure individually:
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
  }
}));
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.disable('x-powered-by');
""".strip()

HEADERS_NGINX = """
# nginx.conf - Add inside the server {} block
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;

# Hide server version
server_tokens off;
""".strip()

# ============================================================
# XSS PREVENTION - Code per framework
# ============================================================

XSS_REACT = """
// React/Next.js - NEVER use dangerouslySetInnerHTML with user input
// WRONG:
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// CORRECT - Use plain text (React escapes automatically):
<div>{userInput}</div>

// If you need to render HTML, use DOMPurify:
// npm install dompurify @types/dompurify
import DOMPurify from 'dompurify';

function SafeHTML({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'target'],
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
""".strip()

XSS_EXPRESS = """
// Express.js - Sanitize input on the backend
// npm install xss

const xss = require('xss');

app.post('/api/comment', (req, res) => {
  // WRONG:
  // const comment = req.body.comment;

  // CORRECT - Sanitize before saving:
  const comment = xss(req.body.comment);
  // Now save to the database
});

// Or use express-validator:
// npm install express-validator
const { body, validationResult } = require('express-validator');

app.post('/api/data',
  body('name').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Input is sanitized
  }
);
""".strip()

# ============================================================
# SQL INJECTION PREVENTION
# ============================================================

SQLI_NODE = """
// Node.js - ALWAYS use parameterized queries
// WRONG (vulnerable to SQLi):
const query = `SELECT * FROM users WHERE id = '${userId}'`;
db.query(query);

// CORRECT with mysql2:
const [rows] = await db.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// CORRECT with pg (PostgreSQL):
const result = await pool.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);

// CORRECT with Prisma (recommended ORM):
const user = await prisma.user.findUnique({
  where: { id: userId }
});

// If you need a raw query in Prisma:
const users = await prisma.$queryRaw`
  SELECT * FROM users WHERE id = ${userId}
`;
// Prisma escapes automatically with template literals
""".strip()

SQLI_PYTHON = """
# Python - ALWAYS use parameterized queries
# WRONG (vulnerable to SQLi):
cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

# CORRECT with psycopg2 (PostgreSQL):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# CORRECT with SQLAlchemy:
from sqlalchemy import text
result = session.execute(
    text("SELECT * FROM users WHERE id = :id"),
    {"id": user_id}
)

# BETTER - Use the SQLAlchemy ORM:
user = session.query(User).filter(User.id == user_id).first()
""".strip()

# ============================================================
# CSRF PROTECTION
# ============================================================

CSRF_NEXTJS = """
// Next.js API Route - Add CSRF verification
// Option 1: Verify the Origin header
export async function POST(request: Request) {
  const origin = request.headers.get('origin');
  const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL];

  if (!origin || !allowedOrigins.includes(origin)) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // Continue with the logic...
}

// Option 2: Use the csrf-csrf package
// npm install csrf-csrf
// See: https://github.com/Psifi-Solutions/csrf-csrf
""".strip()

CSRF_EXPRESS = """
// Express.js - Use csurf or csrf-csrf
// npm install csrf-csrf cookie-parser

const { doubleCsrf } = require('csrf-csrf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__csrf',
  cookieOptions: { httpOnly: true, sameSite: 'strict', secure: true },
});

// Apply to all POST/PUT/DELETE routes
app.use(doubleCsrfProtection);

// Endpoint for the frontend to obtain the token
app.get('/api/csrf-token', (req, res) => {
  res.json({ token: generateToken(req, res) });
});
""".strip()

# ============================================================
# SECRETS / ENV VARS
# ============================================================

SECRETS_NEXTJS = """
// WRONG - Secret hardcoded in code:
const apiKey = "sk-live-abc123def456";
const dbUrl = "postgres://user:pass@host:5432/db";

// CORRECT - Use environment variables:
// 1. Create the .env.local file (NEVER commit this file)
//    API_KEY=sk-live-abc123def456
//    DATABASE_URL=postgres://user:pass@host:5432/db

// 2. Access in code:
const apiKey = process.env.API_KEY;        // Backend only
const dbUrl = process.env.DATABASE_URL;    // Backend only

// IMPORTANT: Variables with NEXT_PUBLIC_ are exposed in the frontend!
// NEVER put secrets in NEXT_PUBLIC_
// process.env.NEXT_PUBLIC_API_URL  -> visible in the browser (OK for public URLs)
// process.env.API_SECRET           -> server only (OK for secrets)

// 3. Add to .gitignore:
//    .env
//    .env.local
//    .env.production
""".strip()

SECRETS_GENERAL = """
# Golden rules for secrets:

1. NEVER put secrets in source code
2. Use .env files + .gitignore
3. In production, use environment variables from your hosting provider
4. Secrets in the frontend are ALWAYS exposed (browser DevTools)
5. Use a secrets manager:
   - Vercel: Environment Variables in the dashboard
   - AWS: Secrets Manager or SSM Parameter Store
   - Firebase: functions.config() or Secret Manager

# If a secret was leaked:
1. REVOKE immediately (generate a new key)
2. Check usage logs for the old key
3. Move to an environment variable
4. Clean from git history:
   git filter-branch --force --index-filter \\
     "git rm --cached --ignore-unmatch path/to/secret" HEAD
""".strip()

# ============================================================
# SSL/HTTPS
# ============================================================

SSL_NGINX = """
# nginx.conf - Force HTTPS redirect
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # Let's Encrypt certificate
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}

# Install Let's Encrypt:
# sudo apt install certbot python3-certbot-nginx
# sudo certbot --nginx -d yourdomain.com
""".strip()

SSL_VERCEL = """
# Vercel / Netlify / Firebase Hosting
# HTTPS is automatic on these platforms!
# Just make sure that:

1. Your custom domain is configured in the dashboard
2. The SSL certificate was automatically provisioned
3. Force HTTPS in the project settings

# vercel.json - Force HTTPS
{
  "redirects": [
    {
      "source": "/(.*)",
      "has": [{ "type": "header", "key": "x-forwarded-proto", "value": "http" }],
      "destination": "https://yourdomain.com/$1",
      "permanent": true
    }
  ]
}
""".strip()

# ============================================================
# COOKIE SECURITY
# ============================================================

COOKIES_EXPRESS = """
// Express.js - Configure secure cookies
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,    // Inaccessible via JavaScript
    secure: true,      // HTTPS only
    sameSite: 'strict', // Protects against CSRF
    maxAge: 3600000,   // 1 hour
  },
}));

// When setting cookies manually:
res.cookie('token', value, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 3600000,
});
""".strip()

# ============================================================
# DIRECTORY/FILE PROTECTION
# ============================================================

DIRECTORY_NGINX = """
# nginx.conf - Block access to sensitive files
location ~ /\\.env { deny all; return 404; }
location ~ /\\.git { deny all; return 404; }
location ~ /\\.htaccess { deny all; return 404; }
location ~ /\\.DS_Store { deny all; return 404; }
location ~ /docker-compose { deny all; return 404; }
location ~ /Dockerfile { deny all; return 404; }
location ~ /package\\.json { deny all; return 404; }
location ~ /composer\\.json { deny all; return 404; }
location ~ \\.(sql|bak|backup|log)$ { deny all; return 404; }
""".strip()

DIRECTORY_VERCEL = """
# vercel.json - Block sensitive routes
{
  "rewrites": [
    { "source": "/.env", "destination": "/404" },
    { "source": "/.git/:path*", "destination": "/404" },
    { "source": "/api/docs", "destination": "/404" }
  ]
}
""".strip()


# ============================================================
# TEMPLATE SELECTOR - Maps vulnerability type to code templates
# ============================================================

def get_remediation_code(vulnerability_type: str, detected_tech: list[str] | None = None) -> str:
    """Get framework-specific remediation code for a vulnerability type.

    Args:
        vulnerability_type: One of 'headers', 'xss', 'sqli', 'csrf',
            'secrets', 'ssl', 'cookies', 'directories'
        detected_tech: List of detected technologies (e.g. ['Next.js', 'Express'])

    Returns:
        Multi-line string with code examples for the most relevant frameworks.
    """
    tech = [t.lower() for t in (detected_tech or [])]

    templates = {
        "headers": [
            ("Next.js", HEADERS_NEXTJS, ["next", "next.js", "react"]),
            ("Express.js", HEADERS_EXPRESS, ["express", "node"]),
            ("Nginx", HEADERS_NGINX, ["nginx"]),
        ],
        "xss": [
            ("React / Next.js", XSS_REACT, ["react", "next", "next.js"]),
            ("Express.js (Backend)", XSS_EXPRESS, ["express", "node"]),
        ],
        "sqli": [
            ("Node.js", SQLI_NODE, ["node", "express", "next", "next.js"]),
            ("Python", SQLI_PYTHON, ["python", "django", "flask", "fastapi"]),
        ],
        "csrf": [
            ("Next.js", CSRF_NEXTJS, ["next", "next.js", "react"]),
            ("Express.js", CSRF_EXPRESS, ["express", "node"]),
        ],
        "secrets": [
            ("Next.js / React", SECRETS_NEXTJS, ["next", "next.js", "react"]),
            ("General", SECRETS_GENERAL, []),
        ],
        "ssl": [
            ("Nginx", SSL_NGINX, ["nginx", "apache"]),
            ("Vercel / Cloud", SSL_VERCEL, ["vercel", "netlify", "firebase"]),
        ],
        "cookies": [
            ("Express.js", COOKIES_EXPRESS, ["express", "node"]),
        ],
        "directories": [
            ("Nginx", DIRECTORY_NGINX, ["nginx"]),
            ("Vercel", DIRECTORY_VERCEL, ["vercel"]),
        ],
    }

    entries = templates.get(vulnerability_type, [])
    if not entries:
        return ""

    # If we know the tech stack, prioritize matching templates
    results = []
    for label, code, match_tech in entries:
        if not match_tech or any(t in tech for t in match_tech):
            results.append(f"### {label}\n```\n{code}\n```")

    # If nothing matched, return all templates
    if not results:
        for label, code, _ in entries:
            results.append(f"### {label}\n```\n{code}\n```")

    return "\n\n".join(results)
