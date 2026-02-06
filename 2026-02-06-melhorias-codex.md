# Melhorias Codex - 2026-02-06

## Escopo
Este documento foca exclusivamente na efetividade funcional dos scanners do HackerPA (cobertura de ataques, profundidade de detecção e lacunas), sem analisar a segurança da própria plataforma.

## Resumo Executivo
O conjunto atual de scanners entrega um baseline bom para encontrar misconfigurações e vulnerabilidades web clássicas em cenário simples.
Ainda existe oportunidade relevante para aumentar cobertura de ataques reais mais avançados, principalmente em:
- Controle de acesso por objeto e por função (BOLA/BFLA).
- Ataques blind/out-of-band (SSRF blind, XSS/SQLi sem reflexão direta).
- Fluxos modernos de API (JSON profundo, GraphQL, WebSocket).
- Exploração de lógica de negócio e upload/parsers.

## Estado Atual por Scanner
### Recon
Ponto forte: fingerprinting inicial e detecção de stack.
Lacuna: pouca profundidade de crawl e baixa correlação com CVEs específicos por versão.

### SSL/TLS
Ponto forte: validade de certificado, redirect HTTP->HTTPS e protocolos legados.
Lacuna: falta análise de cipher suites, cadeia completa, OCSP stapling e hardening TLS avançado.

### Headers
Ponto forte: checagem de presença de headers-chave.
Lacuna: validação semântica limitada de CSP/Permissions-Policy e ausência de score por qualidade da política.

### Secrets
Ponto forte: varredura regex em HTML e JS vinculados.
Lacuna: sem crawl profundo de chunks dinâmicos/sourcemaps e sem validação de secret realmente ativo.

### Directory/Files
Ponto forte: wordlist inicial útil para exposição óbvia.
Lacuna: enumeração não adaptativa por stack e sem descoberta contextual por conteúdo.

### XSS
Ponto forte: detecção de reflexão simples em forms e parâmetros.
Lacuna: não cobre DOM XSS, stored XSS e contexto de execução real em navegador.

### SQLi
Ponto forte: técnicas error-based, boolean-based e time-based.
Lacuna: baixa cobertura de payloads em JSON/body complexo/headers/cookies e maior chance de falso positivo em heurística por tamanho de resposta.

### CSRF
Ponto forte: inspeção de token, SameSite e heurísticas de forms.
Lacuna: não valida enforcement real no backend (requisições sem token e origem cruzada com prova prática).

### SSRF
Ponto forte: payloads internos e endpoints comuns de proxy/fetch.
Lacuna: ausência de infraestrutura OAST para detectar SSRF blind e bypasses modernos de parser/protocol smuggling.

### Endpoint/API
Ponto forte: descoberta básica de endpoints por source + caminhos comuns.
Lacuna: não executa matriz completa de autorização por método/identidade/objeto.

### Subdomain
Ponto forte: brute force + CT logs.
Lacuna: cobertura limitada para takeover, dangling CNAME e expansão por ASN/IPv4/IPv6.

### ZAP
Ponto forte: integração com spider + active scan.
Lacuna: não está no conjunto default de módulos do scan completo e falta política de execução por perfil de risco.

## Oportunidades Prioritárias
### P0 (alto impacto imediato)
- Criar crawler central compartilhado por todos os scanners (profundidade, dedupe, orçamento de requests).
- Implementar scanner dedicado de Access Control (BOLA/BFLA/IDOR) com matriz:
anonimo vs autenticado comum vs privilegiado, e GET/POST/PUT/PATCH/DELETE.
- Adicionar OAST para SSRF blind e outras classes que exigem callback externo.
- Incluir ZAP Passive Scan no fluxo default de scan completo.

### P1 (evolução de profundidade técnica)
- XSS browser-based com Playwright para confirmar execução real e contexto.
- SQLi ampliado para JSON, GraphQL, headers e cookies, com comparação de resposta mais robusta.
- CSRF com validação ativa de rejeição server-side (prova de bloqueio).
- Secrets com varredura de assets dinâmicos e validação de vazamento material.

### P2 (maturidade avançada)
- Scanner de upload/parsers (polyglot, content-type confusion, SVG/XXE, double extension).
- Scanner de lógica de negócio (abuso de fluxo, race/replay).
- Scanner avançado de GraphQL/WebSocket e fuzzing orientado por schema.
- Módulo de threat simulation orientado por tipo de ativo (e-commerce, fintech, SaaS B2B etc.).

## Backlog Sugerido (Sprintável)
1. Implementar `crawler_core` com armazenamento de superfície descoberta e consumo por scanners.
2. Criar `access_control_scanner` com cenários de BOLA/BFLA por endpoint.
3. Integrar `oast_client` com geração de payloads e coleta de callbacks.
4. Adicionar modo `xss_browser` (Playwright) para confirmação de execução.
5. Evoluir `sqli_scanner` para payload injection multi-canal.
6. Criar `upload_abuse_scanner` com suíte mínima de arquivos maliciosos controlados.
7. Tornar `zap` configurável por perfil (`passive-default`, `active-opt-in`).

## Métricas de Sucesso
- Redução de falso positivo em XSS/SQLi.
- Aumento de vulnerabilidades confirmadas com prova reproduzível.
- Cobertura de endpoints autenticados e autorização por objeto.
- Taxa de descoberta em API moderna (JSON/GraphQL/WebSocket).
- Tempo médio de scan mantido dentro de orçamento operacional.

## Próximo Passo Recomendado
Executar primeiro P0 com foco em `crawler_core + access_control_scanner + OAST`, pois isso aumenta cobertura real de forma mais agressiva do que apenas expandir payload lists.
