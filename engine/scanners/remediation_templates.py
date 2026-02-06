"""
HackerPA Engine - Vibe-Coder Remediation Templates

Provides copy-paste ready code snippets for fixing vulnerabilities,
organized by framework/stack. Instead of just saying "fix XSS",
this gives the developer the actual code to implement.
"""

# ============================================================
# SECURITY HEADERS - Code to add per framework
# ============================================================

HEADERS_NEXTJS = """
// next.config.ts - Adicione security headers
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
// Express.js - Instale e configure o helmet
// npm install helmet

const helmet = require('helmet');
const app = express();

app.use(helmet());

// Ou configure individualmente:
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
# nginx.conf - Adicione dentro do bloco server {}
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;

# Esconder versao do servidor
server_tokens off;
""".strip()

# ============================================================
# XSS PREVENTION - Code per framework
# ============================================================

XSS_REACT = """
// React/Next.js - NUNCA use dangerouslySetInnerHTML com input do usuario
// ERRADO:
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// CORRETO - Use texto puro (React escapa automaticamente):
<div>{userInput}</div>

// Se precisar renderizar HTML, use DOMPurify:
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
// Express.js - Sanitize input no backend
// npm install xss

const xss = require('xss');

app.post('/api/comment', (req, res) => {
  // ERRADO:
  // const comment = req.body.comment;

  // CORRETO - Sanitize antes de salvar:
  const comment = xss(req.body.comment);
  // Agora salve no banco
});

// Ou use express-validator:
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
    // Input esta sanitizado
  }
);
""".strip()

# ============================================================
# SQL INJECTION PREVENTION
# ============================================================

SQLI_NODE = """
// Node.js - SEMPRE use parameterized queries
// ERRADO (vulneravel a SQLi):
const query = `SELECT * FROM users WHERE id = '${userId}'`;
db.query(query);

// CORRETO com mysql2:
const [rows] = await db.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// CORRETO com pg (PostgreSQL):
const result = await pool.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);

// CORRETO com Prisma (ORM recomendado):
const user = await prisma.user.findUnique({
  where: { id: userId }
});

// Se precisar de query raw no Prisma:
const users = await prisma.$queryRaw`
  SELECT * FROM users WHERE id = ${userId}
`;
// Prisma escapa automaticamente com template literals
""".strip()

SQLI_PYTHON = """
# Python - SEMPRE use parameterized queries
# ERRADO (vulneravel a SQLi):
cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

# CORRETO com psycopg2 (PostgreSQL):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# CORRETO com SQLAlchemy:
from sqlalchemy import text
result = session.execute(
    text("SELECT * FROM users WHERE id = :id"),
    {"id": user_id}
)

# MELHOR - Use o ORM do SQLAlchemy:
user = session.query(User).filter(User.id == user_id).first()
""".strip()

# ============================================================
# CSRF PROTECTION
# ============================================================

CSRF_NEXTJS = """
// Next.js API Route - Adicione verificacao de CSRF
// Opcao 1: Verifique o header Origin
export async function POST(request: Request) {
  const origin = request.headers.get('origin');
  const allowedOrigins = [process.env.NEXT_PUBLIC_APP_URL];

  if (!origin || !allowedOrigins.includes(origin)) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // Continue com a logica...
}

// Opcao 2: Use o package csrf-csrf
// npm install csrf-csrf
// Veja: https://github.com/Psifi-Solutions/csrf-csrf
""".strip()

CSRF_EXPRESS = """
// Express.js - Use csurf ou csrf-csrf
// npm install csrf-csrf cookie-parser

const { doubleCsrf } = require('csrf-csrf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: '__csrf',
  cookieOptions: { httpOnly: true, sameSite: 'strict', secure: true },
});

// Aplique a todas as rotas POST/PUT/DELETE
app.use(doubleCsrfProtection);

// Endpoint para o frontend obter o token
app.get('/api/csrf-token', (req, res) => {
  res.json({ token: generateToken(req, res) });
});
""".strip()

# ============================================================
# SECRETS / ENV VARS
# ============================================================

SECRETS_NEXTJS = """
// ERRADO - Secret hardcoded no codigo:
const apiKey = "sk-live-abc123def456";
const dbUrl = "postgres://user:pass@host:5432/db";

// CORRETO - Use variaveis de ambiente:
// 1. Crie o arquivo .env.local (NUNCA commite este arquivo)
//    API_KEY=sk-live-abc123def456
//    DATABASE_URL=postgres://user:pass@host:5432/db

// 2. Acesse no codigo:
const apiKey = process.env.API_KEY;        // Backend only
const dbUrl = process.env.DATABASE_URL;    // Backend only

// IMPORTANTE: Variaveis com NEXT_PUBLIC_ sao expostas no frontend!
// NUNCA coloque secrets em NEXT_PUBLIC_
// process.env.NEXT_PUBLIC_API_URL  -> visivel no browser (OK para URLs publicas)
// process.env.API_SECRET           -> apenas no servidor (OK para secrets)

// 3. Adicione ao .gitignore:
//    .env
//    .env.local
//    .env.production
""".strip()

SECRETS_GENERAL = """
# Regras de ouro para secrets:

1. NUNCA coloque secrets no codigo fonte
2. Use .env files + .gitignore
3. Em producao, use variaveis de ambiente do hosting
4. Secrets no frontend sao SEMPRE expostos (browser DevTools)
5. Use um gerenciador de secrets:
   - Vercel: Environment Variables no dashboard
   - AWS: Secrets Manager ou SSM Parameter Store
   - Firebase: functions.config() ou Secret Manager

# Se um secret vazou:
1. REVOGUE imediatamente (gere uma nova chave)
2. Verifique logs de uso da chave antiga
3. Mova para variavel de ambiente
4. Limpe do historico git:
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
    server_name seudominio.com.br;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name seudominio.com.br;

    # Certificado Let's Encrypt
    ssl_certificate /etc/letsencrypt/live/seudominio.com.br/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seudominio.com.br/privkey.pem;

    # Apenas TLS 1.2 e 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}

# Instalar Let's Encrypt:
# sudo apt install certbot python3-certbot-nginx
# sudo certbot --nginx -d seudominio.com.br
""".strip()

SSL_VERCEL = """
# Vercel / Netlify / Firebase Hosting
# HTTPS e automatico nestas plataformas!
# Apenas certifique-se de que:

1. Seu dominio customizado esta configurado no dashboard
2. O certificado SSL foi provisionado automaticamente
3. Force HTTPS nas configuracoes do projeto

# vercel.json - Force HTTPS
{
  "redirects": [
    {
      "source": "/(.*)",
      "has": [{ "type": "header", "key": "x-forwarded-proto", "value": "http" }],
      "destination": "https://seudominio.com.br/$1",
      "permanent": true
    }
  ]
}
""".strip()

# ============================================================
# COOKIE SECURITY
# ============================================================

COOKIES_EXPRESS = """
// Express.js - Configure cookies seguros
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,    // Inacessivel via JavaScript
    secure: true,      // Apenas HTTPS
    sameSite: 'strict', // Protege contra CSRF
    maxAge: 3600000,   // 1 hora
  },
}));

// Ao setar cookies manualmente:
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
# nginx.conf - Bloqueie acesso a arquivos sensiveis
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
# vercel.json - Bloqueie rotas sensiveis
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
            ("Geral", SECRETS_GENERAL, []),
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
