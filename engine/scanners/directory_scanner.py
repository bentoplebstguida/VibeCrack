"""
HackerPA Engine - Directory & Sensitive Files Scanner

Checks for exposed sensitive files and directories like .env, .git,
admin panels, backup files, config files, and other paths that should
not be publicly accessible.
"""

from urllib.parse import urljoin

from engine.scanners.base_scanner import BaseScanner
from engine import config


# Severity classification for different types of exposed paths
PATH_SEVERITY = {
    "/.env": ("critical", "Arquivo .env exposto com variaveis de ambiente", "Contem senhas, API keys, e configuracoes sensiveis do servidor."),
    "/.env.local": ("critical", "Arquivo .env.local exposto", "Contem variaveis de ambiente locais, frequentemente com secrets de producao."),
    "/.env.production": ("critical", "Arquivo .env.production exposto", "Contem variaveis de ambiente de producao com secrets reais."),
    "/.git/config": ("critical", "Repositorio Git exposto", "Atacantes podem baixar todo o codigo fonte, incluindo historico de commits com possiveis secrets."),
    "/.git/HEAD": ("critical", "Repositorio Git exposto (HEAD)", "Confirma que o diretorio .git esta acessivel publicamente."),
    "/dump.sql": ("critical", "Dump de banco de dados exposto", "Contem todos os dados do banco incluindo possiveis senhas e dados pessoais."),
    "/database.sql": ("critical", "Arquivo SQL de banco de dados exposto", "Contem estrutura e possivelmente dados do banco."),
    "/phpinfo.php": ("high", "phpinfo() exposto", "Revela configuracao completa do PHP, caminhos do servidor, e versoes de software."),
    "/info.php": ("high", "Arquivo de informacao PHP exposto", "Pode revelar configuracoes sensiveis do servidor."),
    "/wp-admin/": ("medium", "Painel WordPress admin acessivel", "Painel de administracao do WordPress esta acessivel publicamente."),
    "/admin/": ("medium", "Painel admin acessivel", "Area de administracao acessivel publicamente. Verifique se requer autenticacao."),
    "/administrator/": ("medium", "Painel administrator acessivel", "Area de administracao acessivel publicamente."),
    "/swagger.json": ("medium", "Documentacao Swagger/OpenAPI exposta", "Revela todos os endpoints da API, parametros, e estrutura de dados."),
    "/openapi.json": ("medium", "Documentacao OpenAPI exposta", "Revela todos os endpoints da API publicamente."),
    "/api/docs": ("medium", "Documentacao de API exposta", "Documentacao interativa de API acessivel sem autenticacao."),
    "/server-status": ("medium", "Apache server-status exposto", "Revela informacoes sobre conexoes ativas e configuracao do servidor."),
    "/server-info": ("medium", "Apache server-info exposto", "Revela configuracao detalhada do servidor Apache."),
    "/composer.json": ("medium", "composer.json exposto", "Revela dependencias PHP e suas versoes, util para buscar CVEs."),
    "/package.json": ("low", "package.json exposto", "Revela dependencias Node.js e suas versoes."),
    "/Dockerfile": ("medium", "Dockerfile exposto", "Revela a configuracao do container e possivelmente secrets no build."),
    "/docker-compose.yml": ("medium", "docker-compose.yml exposto", "Revela a arquitetura de servicos e possivelmente credenciais."),
    "/.dockerenv": ("medium", "Container Docker detectado", "O servidor esta rodando em container Docker."),
    "/backup/": ("high", "Diretorio de backup acessivel", "Backups podem conter dados sensiveis, codigo fonte, e configuracoes."),
    "/backups/": ("high", "Diretorio de backups acessivel", "Backups podem conter dados sensiveis e codigo fonte."),
    "/.htaccess": ("medium", "Arquivo .htaccess acessivel", "Revela regras de rewrite, protecoes de diretorio, e configuracao do Apache."),
    "/web.config": ("medium", "web.config exposto", "Revela configuracao do IIS/ASP.NET, possivelmente connection strings."),
    "/robots.txt": ("info", "robots.txt encontrado", "Pode revelar caminhos sensiveis que o site tenta esconder de buscadores."),
    "/sitemap.xml": ("info", "sitemap.xml encontrado", "Mapeia todas as paginas do site."),
    "/.well-known/security.txt": ("info", "security.txt encontrado", "Bom! O site tem um contato de seguranca publicado."),
    "/.DS_Store": ("low", ".DS_Store exposto", "Arquivo de metadata do macOS pode revelar nomes de arquivos no diretorio."),
    "/thumbs.db": ("low", "thumbs.db exposto", "Arquivo de metadata do Windows pode revelar nomes de arquivos."),
    "/.npmrc": ("high", ".npmrc exposto", "Pode conter tokens de autenticacao do npm registry."),
    "/.gitignore": ("info", ".gitignore acessivel", "Revela quais arquivos o projeto ignora, indicando possivel tech stack."),
    "/config.php": ("high", "config.php exposto", "Arquivo de configuracao PHP frequentemente contem credenciais de banco."),
    "/config.yml": ("high", "config.yml exposto", "Arquivo de configuracao YAML pode conter secrets."),
    "/config.json": ("high", "config.json exposto", "Arquivo de configuracao JSON pode conter secrets e API keys."),
    "/test.php": ("medium", "Arquivo de teste PHP acessivel", "Arquivos de teste nao devem estar em producao."),
    "/api/": ("info", "Endpoint de API base acessivel", "Base da API responde. Verifique se requer autenticacao."),
    "/console/": ("high", "Console de debug acessivel", "Console de debug (ex: Werkzeug) esta acessivel publicamente. Permite execucao de codigo."),
    "/debug/": ("high", "Endpoint de debug acessivel", "Modo debug esta ativo em producao. Pode revelar stack traces e informacoes internas."),
    "/trace/": ("medium", "Endpoint trace acessivel", "Pode revelar informacoes de debug e stack traces."),
    "/.vscode/": ("low", "Diretorio .vscode exposto", "Configuracoes do VSCode podem revelar extensoes e settings do desenvolvedor."),
    "/.idea/": ("low", "Diretorio .idea exposto", "Configuracoes do IntelliJ/WebStorm expostas."),
}


class DirectoryScanner(BaseScanner):
    scanner_name = "directory_scanner"

    def run(self) -> None:
        self.log("info", f"Scanning for sensitive files/directories: {self.base_url}")

        found_count = 0

        for path in config.SENSITIVE_PATHS:
            url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
            response = self.make_request(url, allow_redirects=False)

            if response is None:
                continue

            # Consider it found if we get a 200 OK
            if response.status_code == 200:
                # Verify it's not a custom 404 page
                if self._is_real_content(response, path):
                    found_count += 1
                    severity_info = PATH_SEVERITY.get(path, ("medium", f"Caminho sensivel acessivel: {path}", "Este caminho nao deveria estar acessivel publicamente."))
                    severity, title, description = severity_info

                    # Get a snippet of the content for evidence
                    snippet = response.text[:500] if response.text else "(empty response)"

                    self.add_finding(
                        severity=severity,
                        title=title,
                        description=description,
                        evidence={
                            "url": url,
                            "response_snippet": snippet[:200],
                        },
                        remediation=self.get_remediation_with_code("directories", self._get_remediation(path)),
                        owasp_category="A01:2021 - Broken Access Control",
                        cvss_score=self._severity_to_cvss(severity),
                        affected_url=url,
                    )
                    self.log("warning", f"FOUND: {path} (status {response.status_code})")
            elif response.status_code == 403:
                # 403 means the path exists but is protected
                self.log("info", f"Protected (403): {path}")
                self.add_finding(
                    severity="info",
                    title=f"Caminho existe mas retorna 403: {path}",
                    description=f"O caminho '{path}' existe no servidor mas acesso e bloqueado (403 Forbidden). Isso confirma a existencia do recurso.",
                    remediation="Considere retornar 404 em vez de 403 para nao confirmar a existencia de caminhos sensiveis.",
                    owasp_category="A01:2021 - Broken Access Control",
                    affected_url=url,
                )

        self.log("info", f"Directory scan complete. Found {found_count} exposed paths.")

    def _is_real_content(self, response, path: str) -> bool:
        """Try to distinguish real content from custom 404 pages."""
        content = response.text.lower()
        content_length = len(response.text)

        # Very short responses for paths that should have content are suspicious
        if path.endswith((".php", ".json", ".yml", ".xml")) and content_length < 10:
            return False

        # Common 404 page indicators
        not_found_indicators = [
            "page not found",
            "404 not found",
            "404 error",
            "not found",
            "does not exist",
            "pagina nao encontrada",
        ]
        for indicator in not_found_indicators:
            if indicator in content:
                return False

        return True

    def _get_remediation(self, path: str) -> str:
        """Get specific remediation advice based on the path."""
        if ".env" in path:
            return ("1. Remova o arquivo .env do diretorio publico.\n"
                    "2. Bloqueie acesso a arquivos .env no web server (ex: nginx location ~ /\\.env { deny all; }).\n"
                    "3. Use variaveis de ambiente do sistema ou um gerenciador de secrets.\n"
                    "4. Revogue todas as credenciais contidas no arquivo.")
        if ".git" in path:
            return ("1. Remova o diretorio .git do deploy de producao.\n"
                    "2. Bloqueie acesso a /.git no web server.\n"
                    "3. Revise o historico de commits por secrets vazados.\n"
                    "4. Configure seu pipeline de deploy para nao copiar .git.")
        if "admin" in path.lower():
            return ("1. Proteja o painel admin com autenticacao forte.\n"
                    "2. Restrinja acesso por IP se possivel.\n"
                    "3. Use 2FA para acesso administrativo.\n"
                    "4. Considere mudar a URL padrao do painel admin.")
        if "backup" in path.lower() or "dump" in path.lower():
            return ("1. Remova backups do diretorio publico imediatamente.\n"
                    "2. Armazene backups em local seguro (S3 privado, etc).\n"
                    "3. Bloqueie acesso a extensoes de backup (.sql, .bak, .zip).")
        if "swagger" in path.lower() or "openapi" in path.lower() or "api/docs" in path:
            return ("1. Proteja documentacao de API com autenticacao.\n"
                    "2. Desabilite Swagger/OpenAPI em producao.\n"
                    "3. Use autorizacao para acessar a documentacao.")
        if "debug" in path.lower() or "console" in path.lower():
            return ("1. Desabilite modo debug em producao IMEDIATAMENTE.\n"
                    "2. No Flask: app.debug = False. No Django: DEBUG = False.\n"
                    "3. No Express: remova middleware de debug.\n"
                    "4. Console de debug em producao permite execucao remota de codigo.")

        return ("1. Bloqueie acesso a este caminho no web server.\n"
                "2. Remova arquivos desnecessarios do deploy de producao.\n"
                "3. Use .gitignore e scripts de deploy para evitar expor arquivos sensiveis.")

    def _severity_to_cvss(self, severity: str) -> float:
        """Map severity to approximate CVSS score."""
        return {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
            "info": 0.0,
        }.get(severity, 5.0)
