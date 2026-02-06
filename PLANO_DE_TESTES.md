# HackerPA - Plano de Testes End-to-End

## Pre-requisitos

### 1. Ambiente de Teste (Alvos Seguros)
Nunca teste contra sites que voce nao tem autorizacao. Use estes alvos:

```bash
# OWASP Juice Shop (vulneravel propositalmente)
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVWA - Damn Vulnerable Web App
docker run -d -p 8081:80 vulnerables/web-dvwa

# Seu proprio site (se tiver um em staging)
```

### 2. Infraestrutura HackerPA
```bash
# Terminal 1: Frontend
cd frontend
npm run dev -- --port 3005

# Terminal 2: Engine (Docker)
cd engine/docker
docker-compose up --build

# OU Engine (local, sem Docker)
cd engine
pip install -r requirements.txt
python -m engine.orchestrator.main
```

### 3. Firebase
- Firestore rules deployed (`firebase deploy --only firestore:rules`)
- Service account key em `serviceAccountKey.json`
- `.env.local` com credenciais corretas no frontend

---

## Fase 1: Testes de Frontend

### T1.1 - Autenticacao
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Login com email/senha | Criar conta e fazer login | Redirect para /dashboard |
| 2 | Login com Google | Clicar "Entrar com Google" | Login via popup OAuth |
| 3 | Logout | Clicar botao de sair na sidebar | Redirect para /login |
| 4 | Acesso sem login | Navegar para /dashboard direto | Redirect para /login |
| 5 | Persistencia de sessao | Fazer login e recarregar pagina | Continua logado |

### T1.2 - Projetos (CRUD)
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Criar projeto | Preencher nome + dominio + descricao | Projeto aparece na lista |
| 2 | Validacao de dominio | Inserir dominio invalido | Mensagem de erro |
| 3 | Editar projeto | Clicar editar, mudar nome | Nome atualizado |
| 4 | Deletar projeto | Clicar deletar | Projeto removido da lista |
| 5 | Isolamento de usuario | Login com outra conta | Nao ve projetos do primeiro |

### T1.3 - Iniciar Scan
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Scan completo | Clicar "Escanear" num projeto | Documento criado no Firestore com status=pending |
| 2 | Progresso real-time | Observar pagina de scan detail | Barra de progresso atualiza |
| 3 | Fases do scan | Durante execucao | Labels das fases mudam (Recon -> SSL -> Headers...) |
| 4 | Scan completado | Aguardar conclusao | Status muda para "Concluido", score aparece |
| 5 | Scan com falha | Desligar engine durante scan | Status muda para "failed" |

### T1.4 - Visualizacao de Resultados
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Score e grade | Abrir scan concluido | Score 0-100 e grade A-F visivel |
| 2 | Resumo por severidade | Abrir scan concluido | Contadores critical/high/medium/low/info |
| 3 | Lista de vulnerabilidades | Scroll na pagina | Cards com titulo, severidade, descricao |
| 4 | Expandir vulnerabilidade | Clicar num card | Mostra evidencia, remediation com codigo |
| 5 | Logs do scan | Scroll ate o final | Timeline de logs com timestamps |
| 6 | Tech detectadas | Cabecalho do scan | Tags com tecnologias detectadas |
| 7 | Download PDF | Clicar "Baixar Relatorio PDF" | PDF baixa com relatorio completo |

### T1.5 - Dashboard e Reports
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Estatisticas | Dashboard principal | Cards com total projetos, scans, score medio |
| 2 | Benchmark | Pagina Reports | Barras comparativas entre projetos |
| 3 | Historico de scores | Pagina Reports | Timeline mostrando evolucao |

---

## Fase 2: Testes do Engine (Scanners)

### T2.1 - Recon Scanner
**Alvo**: Juice Shop (localhost:3000)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Deteccao de tecnologias | Detecta Express/Node.js via headers |
| 2 | Deteccao via HTML | Detecta Angular (Juice Shop usa Angular) |
| 3 | HTTP methods | Reporta metodos perigosos se habilitados |
| 4 | Cookie security | Verifica flags Secure/HttpOnly/SameSite |
| 5 | Tech salva no Firestore | Campo `detectedTech` preenchido no scan doc |

### T2.2 - SSL Scanner
**Alvo**: Qualquer site HTTPS (ex: google.com)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Certificado valido | Log "Certificate valid for X days" |
| 2 | HTTPS redirect | Verifica redirect 301 de HTTP->HTTPS |
| 3 | TLS versoes | Reporta se TLSv1.0/1.1 esta ativo |
| 4 | Certificado invalido | (self-signed) Reporta como critico |

### T2.3 - Headers Scanner
**Alvo**: Juice Shop (localhost:3000)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Headers ausentes | Reporta CSP, HSTS, X-Frame-Options ausentes |
| 2 | Header Server | Reporta info disclosure do header Server |
| 3 | X-Powered-By | Reporta info disclosure do Express |
| 4 | Remediation com codigo | Remediation inclui snippet Next.js/Express/Nginx |

### T2.4 - Secrets Scanner
**Alvo**: Site com API keys expostas (ou criar pagina de teste)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | API key no HTML | Detecta e reporta como finding |
| 2 | Secret em JS bundle | Faz fetch de .js e encontra tokens |
| 3 | Masking | Evidence mostra secret mascarado (abc****xyz) |
| 4 | Severidade correta | Private key = critical, API key = high |

### T2.5 - Directory Scanner
**Alvo**: Juice Shop (localhost:3000)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | /robots.txt | Encontra e reporta como info |
| 2 | Paths sensiveis | Testa todos 45+ paths |
| 3 | Custom 404 detection | Nao reporta false positives de paginas 404 customizadas |
| 4 | Remediation com codigo | Inclui snippets Nginx/Vercel |

### T2.6 - XSS Scanner
**Alvo**: DVWA (localhost:8081) com security=low

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Reflected XSS em form | Detecta XSS no form de busca |
| 2 | XSS em URL param | Detecta XSS em parametros da URL |
| 3 | Payload confirmado | Evidence mostra payload refletido |
| 4 | Remediation com codigo | Inclui snippet DOMPurify/React |

### T2.7 - SQLi Scanner
**Alvo**: DVWA (localhost:8081) com security=low

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Error-based SQLi | Detecta erro SQL na resposta |
| 2 | Boolean-based SQLi | Detecta diferenca TRUE vs FALSE |
| 3 | Time-based SQLi | Detecta delay do SLEEP |
| 4 | Non-destructive | Nao usa DROP/DELETE payloads |
| 5 | Remediation com codigo | Inclui snippet parameterized queries |

### T2.8 - CSRF Scanner
**Alvo**: DVWA ou Juice Shop

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | Form sem token | Detecta POST forms sem CSRF token |
| 2 | SameSite cookie check | Verifica atributo SameSite |
| 3 | GET state-change | Detecta forms GET que fazem state change |

### T2.9 - SSRF Scanner
**Alvo**: Juice Shop

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | URL endpoints | Testa endpoints comuns de proxy/fetch |
| 2 | Payload injection | Testa payloads de localhost/metadata |
| 3 | RCE indicators | Verifica sinais de command execution |

### T2.10 - Subdomain Scanner
**Alvo**: Dominio real com subdomains (ex: empresa com staging)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | DNS brute-force | Descobre subdomains comuns (www, mail, api) |
| 2 | CT logs (crt.sh) | Consulta Certificate Transparency |
| 3 | Risky subdomains | Flagra dev/staging/test como high severity |

### T2.11 - Endpoint Scanner
**Alvo**: Juice Shop

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | API discovery | Descobre endpoints de API |
| 2 | Auth testing | Verifica quais endpoints nao pedem auth |
| 3 | Error page detection | Detecta paginas de debug/stack trace |

### T2.12 - ZAP Scanner
**Alvo**: Juice Shop (requer Docker com ZAP)

| # | Teste | Resultado esperado |
|---|-------|-------------------|
| 1 | ZAP disponivel | Conecta ao container ZAP |
| 2 | Spider | Crawl descobre paginas |
| 3 | Active scan | Executa scan ativo |
| 4 | Import alerts | Alertas ZAP viram findings no HackerPA |
| 5 | ZAP indisponivel | Log gracioso quando ZAP nao esta rodando |

---

## Fase 3: Testes de Integracao

### T3.1 - Circuit Breaker
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Servidor lento | Alvo com response time > 10s | Circuit abre, log de warning |
| 2 | Muitos erros | Alvo retorna 5+ errors | Circuit abre, pausa requests |
| 3 | Cooldown | Esperar 30s apos circuit abrir | Circuit fecha, retoma scan |

### T3.2 - Scoring
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Score de 100 | Scan sem vulnerabilidades | Score = 100, Grade = A+ |
| 2 | Penalidades | Scan com 1 critical + 2 high | Score reduzido corretamente |
| 3 | Score por categoria | Verificar no Firestore | Categorias com scores individuais |
| 4 | Historico de scores | Fazer 2+ scans do mesmo projeto | Collection scores_history populada |
| 5 | Projeto atualizado | Apos scan completo | currentScore e currentGrade no projeto |

### T3.3 - PDF Report
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Geracao de PDF | Scan completo | PDF gerado e uploadado |
| 2 | Secao executiva | Abrir PDF | Resumo com gauges e risk assessment |
| 3 | Secao tecnica | Abrir PDF | Lista detalhada de vulnerabilidades |
| 4 | Download via frontend | Clicar botao "Baixar PDF" | PDF baixa no browser |

### T3.4 - Remediation Templates
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Deteccao Next.js | Scan em site Next.js | Remediation inclui next.config.ts snippets |
| 2 | Deteccao Express | Scan em site Express | Remediation inclui helmet/express snippets |
| 3 | Fallback geral | Scan em site sem tech detectada | Inclui todos os templates |
| 4 | Codigo copiavel | Verificar no frontend | Snippets em bloco de codigo formatado |

---

## Fase 4: Testes de Seguranca do Proprio HackerPA

### T4.1 - Firestore Rules
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Ler projetos de outro | Tentar via SDK/REST | Acesso negado |
| 2 | Escrever vuln como user | Tentar adicionar vulnerability | Acesso negado (apenas engine) |
| 3 | Deletar scan de outro | Tentar via SDK/REST | Acesso negado |

### T4.2 - Service Account Key
| # | Teste | Como testar | Resultado esperado |
|---|-------|-------------|-------------------|
| 1 | Key no .gitignore | `git status` | serviceAccountKey.json nao tracked |
| 2 | Key nao no frontend | Build do frontend | Key nao exposta no bundle JS |

---

## Checklist de Execucao

```
[ ] T1.1 - Autenticacao (5 testes)
[ ] T1.2 - Projetos CRUD (5 testes)
[ ] T1.3 - Iniciar Scan (5 testes)
[ ] T1.4 - Resultados (7 testes)
[ ] T1.5 - Dashboard/Reports (3 testes)
[ ] T2.1 - Recon Scanner (5 testes)
[ ] T2.2 - SSL Scanner (4 testes)
[ ] T2.3 - Headers Scanner (4 testes)
[ ] T2.4 - Secrets Scanner (4 testes)
[ ] T2.5 - Directory Scanner (4 testes)
[ ] T2.6 - XSS Scanner (4 testes)
[ ] T2.7 - SQLi Scanner (5 testes)
[ ] T2.8 - CSRF Scanner (3 testes)
[ ] T2.9 - SSRF Scanner (3 testes)
[ ] T2.10 - Subdomain Scanner (3 testes)
[ ] T2.11 - Endpoint Scanner (3 testes)
[ ] T2.12 - ZAP Scanner (5 testes)
[ ] T3.1 - Circuit Breaker (3 testes)
[ ] T3.2 - Scoring (5 testes)
[ ] T3.3 - PDF Report (4 testes)
[ ] T3.4 - Remediation Templates (4 testes)
[ ] T4.1 - Firestore Rules (3 testes)
[ ] T4.2 - Service Account Key (2 testes)

Total: ~90 testes
```

## Ordem Recomendada de Execucao

1. **Primeiro**: T4.2 (seguranca da key) + T1.1 (login) - garantir que o basico funciona
2. **Segundo**: T1.2 + T1.3 (CRUD + iniciar scan) - fluxo principal
3. **Terceiro**: T2.1-T2.5 (scanners basicos contra Juice Shop)
4. **Quarto**: T2.6-T2.7 (XSS + SQLi contra DVWA)
5. **Quinto**: T2.8-T2.12 + T3.x (scanners avancados + integracao)
6. **Por ultimo**: T4.1 (Firestore rules) - seguranca do proprio app
