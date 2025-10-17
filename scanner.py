"""
NetSereno - OWASP Top 10 Security Scanner
Updated October 2025
"""

import requests
import socket
import ssl
import re
import json
import datetime
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER
import warnings
warnings.filterwarnings('ignore')

class OWASPScanner:
    """
    Comprehensive OWASP Top 10 (2021) vulnerability scanner
    Enhanced with 2025 security best practices
    """
    
    def __init__(self, target_url, scan_id=None):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.parsed_url = urlparse(self.target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.scan_id = scan_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ip = None
        self.results = {}
        self.scan_start = None
        self.scan_end = None
        self.progress = 0
        self.status = "Iniciando..."
        
        try:
            self.ip = socket.gethostbyname(self.domain)
        except:
            self.ip = "No se pudo resolver"
            
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        
        # Payloads actualizados para 2025
        self.sql_payloads = [
            "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 #", "admin' --",
            "' UNION SELECT NULL--", "1' ORDER BY 1--", "' AND 1=2--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        self.sensitive_files = [
            "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
            "/.DS_Store", "/web.config", "/phpinfo.php", "/backup.sql",
            "/robots.txt", "/.htaccess", "/composer.json", "/package.json"
        ]

    def run_scan(self):
        """Execute complete security scan"""
        self.scan_start = datetime.datetime.now()
        
        tests = [
            (12, "Inyección SQL y comandos", self.check_injection),
            (24, "Autenticación rota", self.check_broken_authentication),
            (36, "Exposición de datos sensibles", self.check_sensitive_data_exposure),
            (48, "Control de acceso roto", self.check_broken_access_control),
            (60, "Configuración incorrecta", self.check_security_misconfiguration),
            (72, "Cross-Site Scripting", self.check_xss),
            (84, "Componentes vulnerables", self.check_vulnerable_components),
            (96, "Cabeceras de seguridad", self.check_security_headers),
            (100, "Configuración del servidor", self.check_server_config)
        ]
        
        for progress, description, test_func in tests:
            self.progress = progress
            self.status = description
            try:
                key = test_func.__name__.replace('check_', '')
                self.results[key] = test_func()
            except Exception as e:
                self.results[key] = {
                    "vulnerable": False,
                    "findings": [],
                    "error": str(e)
                }
        
        self.scan_end = datetime.datetime.now()
        return self.results

    def check_injection(self):
        """A01/A03:2021 - Injection"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}
        
        try:
            params = self._find_url_parameters()
            
            for param in params[:5]:  # Limit parameters
                for payload in self.sql_payloads[:3]:
                    test_url = self._inject_parameter(param, payload)
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                        
                        sql_errors = ["SQL syntax", "mysql_", "ORA-", "PostgreSQL", "SQLite", "syntax error"]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                results["findings"].append({
                                    "type": "Inyección SQL",
                                    "url": test_url[:100] + "...",
                                    "parameter": param,
                                    "severity": "Critical"
                                })
                                results["vulnerable"] = True
                                break
                    except:
                        continue
                        
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades de inyección"})
        
        return results

    def check_broken_authentication(self):
        """A02/A07:2021 - Authentication Failures"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}
        
        try:
            login_paths = ["/login", "/signin", "/admin", "/auth", "/iniciar-sesion"]
            
            for path in login_paths:
                login_url = f"{self.base_url}{path}"
                try:
                    response = requests.get(login_url, headers=self.headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        if not login_url.startswith("https"):
                            results["findings"].append({
                                "type": "Login sin HTTPS",
                                "url": login_url,
                                "description": "Página de login accesible vía HTTP inseguro",
                                "severity": "Critical"
                            })
                            results["vulnerable"] = True
                except:
                    continue
            
            # Check cookies
            try:
                response = requests.get(self.target_url, headers=self.headers, timeout=5, verify=False)
                
                for cookie in response.cookies:
                    if not cookie.secure and self.target_url.startswith('https'):
                        results["findings"].append({
                            "type": "Cookie insegura",
                            "description": f"Cookie '{cookie.name}' sin flag Secure",
                            "severity": "High"
                        })
                        results["vulnerable"] = True
                        break  # Limit findings
                        
            except:
                pass
                
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron fallos de autenticación"})
        
        return results

    def check_sensitive_data_exposure(self):
        """A03/A02:2021 - Cryptographic Failures"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}
        
        try:
            # Check HTTPS
            if not self.target_url.startswith('https'):
                results["findings"].append({
                    "type": "Sin cifrado HTTPS",
                    "url": self.target_url,
                    "description": "El sitio no utiliza cifrado HTTPS",
                    "severity": "Critical"
                })
                results["vulnerable"] = True
            
            # Check HSTS
            try:
                response = requests.get(self.target_url, headers=self.headers, timeout=5, verify=False)
                if 'Strict-Transport-Security' not in response.headers and self.target_url.startswith('https'):
                    results["findings"].append({
                        "type": "HSTS no configurado",
                        "description": "Falta cabecera Strict-Transport-Security",
                        "severity": "Medium"
                    })
                    results["vulnerable"] = True
            except:
                pass
            
            # Check sensitive files
            for file_path in self.sensitive_files[:8]:
                try:
                    file_url = f"{self.base_url}{file_path}"
                    response = requests.head(file_url, headers=self.headers, timeout=3, verify=False)
                    
                    if response.status_code == 200:
                        results["findings"].append({
                            "type": "Archivo sensible expuesto",
                            "url": file_url,
                            "severity": "High"
                        })
                        results["vulnerable"] = True
                except:
                    pass
                    
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectó exposición de datos sensibles"})
        
        return results

    def check_broken_access_control(self):
        """A04/A01:2021 - Broken Access Control"""
        results = {"vulnerable": False, "findings": [], "severity": "Critical"}
        
        try:
            protected_paths = ["/admin", "/dashboard", "/panel", "/api/users", "/config", "/settings"]
            
            for path in protected_paths[:5]:
                try:
                    resource_url = f"{self.base_url}{path}"
                    response = requests.get(resource_url, headers=self.headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        login_indicators = ["login", "password", "authenticate", "contraseña"]
                        
                        if not any(ind in response.text.lower() for ind in login_indicators):
                            results["findings"].append({
                                "type": "Recurso protegido accesible",
                                "url": resource_url,
                                "severity": "Critical"
                            })
                            results["vulnerable"] = True
                            break
                except:
                    continue
                    
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron problemas de control de acceso"})
        
        return results

    def check_security_misconfiguration(self):
        """A05/A05:2021 - Security Misconfiguration"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}
        
        try:
            # Check directory listing
            dirs = ["/images", "/uploads", "/admin", "/backup", "/files"]
            
            for dir_path in dirs[:4]:
                try:
                    dir_url = f"{self.base_url}{dir_path}"
                    response = requests.get(dir_url, headers=self.headers, timeout=4, verify=False)
                    
                    if "Index of" in response.text or "Directory listing" in response.text:
                        results["findings"].append({
                            "type": "Listado de directorios",
                            "url": dir_url,
                            "severity": "Medium"
                        })
                        results["vulnerable"] = True
                except:
                    continue
            
            # Check default admin pages
            default_pages = ["/phpmyadmin", "/wp-admin", "/adminer.php", "/admin.php"]
            
            for page in default_pages[:3]:
                try:
                    page_url = f"{self.base_url}{page}"
                    response = requests.get(page_url, headers=self.headers, timeout=4, verify=False)
                    
                    if response.status_code == 200:
                        results["findings"].append({
                            "type": "Panel admin accesible",
                            "url": page_url,
                            "severity": "High"
                        })
                        results["vulnerable"] = True
                        break
                except:
                    continue
                    
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron configuraciones incorrectas"})
        
        return results

    def check_xss(self):
        """A06/A03:2021 - Cross-Site Scripting"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}
        
        try:
            params = self._find_url_parameters()
            
            for param in params[:3]:
                for payload in self.xss_payloads[:2]:
                    test_url = self._inject_parameter(param, payload)
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                        
                        if payload in response.text or quote(payload) in response.text:
                            results["findings"].append({
                                "type": "XSS Reflejado",
                                "parameter": param,
                                "severity": "High"
                            })
                            results["vulnerable"] = True
                            break
                    except:
                        continue
                            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron vulnerabilidades XSS"})
        
        return results

    def check_vulnerable_components(self):
        """A07/A06:2021 - Vulnerable Components"""
        results = {"vulnerable": False, "findings": [], "severity": "High"}
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=5, verify=False)
            
            server = response.headers.get('Server', '')
            if server:
                vulnerable_versions = ['Apache/2.2', 'Apache/2.4.1', 'nginx/1.10', 'IIS/6.0', 'IIS/7.0']
                
                for version in vulnerable_versions:
                    if version.lower() in server.lower():
                        results["findings"].append({
                            "type": "Servidor obsoleto",
                            "version": server,
                            "severity": "High"
                        })
                        results["vulnerable"] = True
                        break
                
            # Check for X-Powered-By
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                results["findings"].append({
                    "type": "Tecnología expuesta",
                    "header": f"X-Powered-By: {powered_by}",
                    "severity": "Info"
                })
                
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "No se detectaron componentes vulnerables"})
        
        return results

    def check_security_headers(self):
        """Security Headers Check (2025 Best Practices)"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}
        
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=5, verify=False)
            headers = response.headers
            
            required_headers = {
                'X-Frame-Options': 'Clickjacking',
                'X-Content-Type-Options': 'MIME-sniffing',
                'Strict-Transport-Security': 'HTTPS (HSTS)',
                'Content-Security-Policy': 'XSS y ataques de inyección'
            }
            
            missing = []
            for header, purpose in required_headers.items():
                if header not in headers:
                    missing.append(header)
                    results["vulnerable"] = True
            
            if missing:
                results["findings"].append({
                    "type": "Cabeceras faltantes",
                    "headers": ", ".join(missing[:3]),  # Limit display
                    "severity": "Medium"
                })
                    
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "Cabeceras configuradas correctamente"})
        
        return results

    def check_server_config(self):
        """Server Configuration Check"""
        results = {"vulnerable": False, "findings": [], "severity": "Medium"}
        
        try:
            # Check HTTP methods
            methods = ['PUT', 'DELETE', 'TRACE']
            dangerous = []
            
            for method in methods:
                try:
                    response = requests.request(method, self.target_url, headers=self.headers, timeout=3, verify=False)
                    if response.status_code < 405:
                        dangerous.append(method)
                except:
                    pass
            
            if dangerous:
                results["findings"].append({
                    "type": "Métodos HTTP peligrosos",
                    "methods": ", ".join(dangerous),
                    "severity": "High"
                })
                results["vulnerable"] = True
            
            # Check IP
            results["findings"].append({
                "type": "Información del servidor",
                "ip": self.ip,
                "severity": "Info"
            })
                    
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append({"info": "Configuración del servidor correcta"})
        
        return results

    def generate_pdf_report(self, output_path):
        """Generate PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, 
                                    textColor=colors.HexColor('#1a237e'), alignment=TA_CENTER)
        
        story.append(Paragraph("NetSereno", title_style))
        story.append(Paragraph("Informe de Seguridad Web", styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        
        # Info
        info_data = [
            ["URL:", self.target_url],
            ["IP:", self.ip],
            ["Fecha:", self.scan_start.strftime('%d/%m/%Y %H:%M:%S')],
            ["Duración:", f"{(self.scan_end - self.scan_start).total_seconds():.1f}s"]
        ]
        
        info_table = Table(info_data, colWidths=[1.5*inch, 4.5*inch])
        info_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold')
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 0.4*inch))
        
        # Summary
        story.append(Paragraph("Resumen Ejecutivo", styles['Heading2']))
        total_vulns = sum(1 for r in self.results.values() if r.get('vulnerable', False))
        story.append(Paragraph(f"Se identificaron {total_vulns} categorías con vulnerabilidades.", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Findings
        story.append(Paragraph("Hallazgos Detallados", styles['Heading2']))
        
        category_names = {
            'injection': 'Inyección',
            'broken_authentication': 'Autenticación',
            'sensitive_data_exposure': 'Datos Sensibles',
            'broken_access_control': 'Control de Acceso',
            'security_misconfiguration': 'Configuración',
            'xss': 'XSS',
            'vulnerable_components': 'Componentes',
            'security_headers': 'Cabeceras',
            'server_config': 'Servidor'
        }
        
        for key, result in self.results.items():
            story.append(Paragraph(category_names.get(key, key), styles['Heading3']))
            
            for finding in result.get('findings', [])[:5]:  # Limit findings
                if 'info' in finding:
                    story.append(Paragraph(f"✓ {finding['info']}", styles['Normal']))
                else:
                    text = f"<b>{finding.get('type', 'N/A')}</b><br/>"
                    if 'url' in finding:
                        text += f"URL: {finding['url']}<br/>"
                    if 'description' in finding:
                        text += f"{finding['description']}<br/>"
                    story.append(Paragraph(text, styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            story.append(Spacer(1, 0.2*inch))
        
        doc.build(story)

    def _find_url_parameters(self):
        """Extract URL parameters"""
        params = []
        if '?' in self.target_url:
            query = self.target_url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        return params

    def _inject_parameter(self, param, payload):
        """Inject payload into parameter"""
        if '?' in self.target_url:
            base, query = self.target_url.split('?', 1)
            params = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
            params[param] = quote(payload)
            return f"{base}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        return f"{self.target_url}?{param}={quote(payload)}"

    def get_summary(self):
        """Get scan summary"""
        return {
            'total_vulnerabilities': sum(1 for r in self.results.values() if r.get('vulnerable', False)),
            'critical': sum(1 for r in self.results.values() if r.get('vulnerable') and r.get('severity') == 'Critical'),
            'high': sum(1 for r in self.results.values() if r.get('vulnerable') and r.get('severity') == 'High'),
            'medium': sum(1 for r in self.results.values() if r.get('vulnerable') and r.get('severity') == 'Medium'),
            'duration': (self.scan_end - self.scan_start).total_seconds() if self.scan_end else 0
        }
