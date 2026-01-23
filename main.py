"""
NetSereno - Enterprise Vulnerability Scanner
Flask API Backend
Version 2.0 - January 2026
"""

from flask import Flask, render_template, request, jsonify, send_file
from scanner import VulnerabilityScanner, ScanProfile
import os
import threading
import time
import uuid
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'netsereno-enterprise-2026')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Store active scans
active_scans = {}

# Scan profiles mapping
PROFILE_MAP = {
    'quick': ScanProfile.QUICK,
    'standard': ScanProfile.STANDARD,
    'deep': ScanProfile.DEEP,
    'full': ScanProfile.FULL,
}


@app.route('/')
def index():
    """Serve the main scanner interface"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    Initiate a new vulnerability scan

    Request body:
    {
        "url": "https://example.com",
        "profile": "standard"  # quick, standard, deep, full
    }
    """
    try:
        data = request.json

        if not data:
            return jsonify({'error': 'Datos JSON requeridos'}), 400

        target_url = data.get('url', '').strip()
        profile_name = data.get('profile', 'standard').lower()

        if not target_url:
            return jsonify({'error': 'URL requerida'}), 400

        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'http://{target_url}'

        # Get scan profile
        profile = PROFILE_MAP.get(profile_name, ScanProfile.STANDARD)

        # Generate unique scan ID
        scan_id = f"{uuid.uuid4().hex[:12]}_{int(time.time())}"

        # Create scanner instance
        scanner = VulnerabilityScanner(target_url, scan_id=scan_id, profile=profile)

        # Store scanner reference
        active_scans[scan_id] = {
            'scanner': scanner,
            'status': 'running',
            'started_at': time.time(),
            'profile': profile_name,
        }

        # Run scan in background thread
        def run_scan():
            try:
                logger.info(f"Starting scan {scan_id} for {target_url} with profile {profile_name}")
                scanner.run_scan()

                # Generate PDF report
                pdf_path = f"/tmp/netsereno_{scan_id}.pdf"
                scanner.generate_pdf_report(pdf_path)

                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['completed_at'] = time.time()
                logger.info(f"Scan {scan_id} completed successfully")

            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {str(e)}")
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = str(e)

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return jsonify({
            'scan_id': scan_id,
            'message': 'Escaneo iniciado',
            'profile': profile_name,
            'target': target_url
        })

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': f'Error interno: {str(e)}'}), 500


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    """Get scan progress and status"""
    scan_data = active_scans.get(scan_id)

    if not scan_data:
        return jsonify({'error': 'Escaneo no encontrado'}), 404

    scanner = scan_data['scanner']

    return jsonify({
        'scan_id': scan_id,
        'progress': scanner.progress,
        'status': scanner.status,
        'completed': scanner.progress >= 100,
        'profile': scan_data.get('profile', 'standard'),
        'total_tests': scanner.total_tests,
        'completed_tests': scanner.completed_tests,
    })


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def scan_results(scan_id):
    """Get detailed scan results"""
    scan_data = active_scans.get(scan_id)

    if not scan_data:
        return jsonify({'error': 'Escaneo no encontrado'}), 404

    scanner = scan_data['scanner']

    if scanner.progress < 100:
        return jsonify({'error': 'Escaneo en progreso', 'progress': scanner.progress}), 400

    summary = scanner.get_summary()

    return jsonify({
        'scan_id': scan_id,
        'results': scanner.results,
        'summary': summary,
        'target': scanner.target_url,
        'ip': scanner.ip,
        'domain': scanner.domain,
        'profile': scan_data.get('profile', 'standard'),
        'scan_time': scanner.scan_start.strftime('%d/%m/%Y %H:%M:%S') if scanner.scan_start else None,
        'open_ports': scanner.open_ports,
        'services': scanner.services,
        'ssl_info': scanner.ssl_info,
        'cms_detected': scanner.cms_detected,
        'technologies': scanner.technologies,
        'vulnerabilities': scanner.vulnerabilities[:50],  # Limit to 50 for API response
    })


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    """Download PDF report"""
    pdf_path = f"/tmp/netsereno_{scan_id}.pdf"

    if not os.path.exists(pdf_path):
        # Try to generate if scan exists
        scan_data = active_scans.get(scan_id)
        if scan_data and scan_data['scanner'].progress >= 100:
            try:
                scan_data['scanner'].generate_pdf_report(pdf_path)
            except Exception as e:
                logger.error(f"Error generating report: {str(e)}")
                return jsonify({'error': 'Error generando reporte'}), 500
        else:
            return jsonify({'error': 'Reporte no encontrado'}), 404

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f'netsereno_security_report_{scan_id}.pdf',
        mimetype='application/pdf'
    )


@app.route('/api/scan/<scan_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(scan_id):
    """Get only the vulnerabilities found"""
    scan_data = active_scans.get(scan_id)

    if not scan_data:
        return jsonify({'error': 'Escaneo no encontrado'}), 404

    scanner = scan_data['scanner']

    if scanner.progress < 100:
        return jsonify({'error': 'Escaneo en progreso'}), 400

    # Filter and sort vulnerabilities by severity
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}

    sorted_vulns = sorted(
        scanner.vulnerabilities,
        key=lambda x: severity_order.get(x.get('severity', 'Info'), 5)
    )

    return jsonify({
        'scan_id': scan_id,
        'total': len(sorted_vulns),
        'vulnerabilities': sorted_vulns
    })


@app.route('/api/profiles', methods=['GET'])
def get_profiles():
    """Get available scan profiles and their descriptions"""
    profiles = [
        {
            'id': 'quick',
            'name': 'Rápido',
            'description': 'Escaneo básico de puertos principales y vulnerabilidades web comunes',
            'estimated_time': '1-2 minutos',
            'tests': ['Puertos principales (10)', 'SSL/TLS', 'Cabeceras', 'Inyección SQL', 'XSS', 'Archivos sensibles']
        },
        {
            'id': 'standard',
            'name': 'Estándar',
            'description': 'Análisis equilibrado con detección de CMS, servicios y configuración',
            'estimated_time': '3-5 minutos',
            'tests': ['Puertos comunes (22)', 'Servicios', 'SSL completo', 'CMS', 'Todas las inyecciones', 'CORS', 'Cookies']
        },
        {
            'id': 'deep',
            'name': 'Profundo',
            'description': 'Escaneo exhaustivo con pruebas avanzadas y detección extendida',
            'estimated_time': '5-10 minutos',
            'tests': ['Puertos extendidos (50+)', 'Servicios avanzados', 'Inyección de comandos', 'LFI/RFI', 'CSRF', 'Subdomain takeover']
        },
        {
            'id': 'full',
            'name': 'Completo',
            'description': 'Auditoría completa tipo OpenVAS con todas las pruebas disponibles',
            'estimated_time': '10-20 minutos',
            'tests': ['Todos los puertos', 'Todas las pruebas de seguridad', 'Análisis profundo de componentes']
        }
    ]

    return jsonify({'profiles': profiles})


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all active and recent scans"""
    scans = []

    for scan_id, scan_data in active_scans.items():
        scanner = scan_data['scanner']
        scans.append({
            'scan_id': scan_id,
            'target': scanner.target_url,
            'progress': scanner.progress,
            'status': scan_data.get('status', 'unknown'),
            'profile': scan_data.get('profile', 'standard'),
            'started_at': scan_data.get('started_at'),
        })

    # Sort by start time, most recent first
    scans.sort(key=lambda x: x.get('started_at', 0), reverse=True)

    return jsonify({'scans': scans[:20]})  # Return last 20 scans


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'active_scans': len([s for s in active_scans.values() if s.get('status') == 'running']),
        'total_scans': len(active_scans),
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Recurso no encontrado'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Error interno del servidor'}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Solicitud demasiado grande'}), 413


# Cleanup old scans periodically
def cleanup_old_scans():
    """Remove scans older than 1 hour"""
    current_time = time.time()
    max_age = 3600  # 1 hour

    scans_to_remove = []
    for scan_id, scan_data in active_scans.items():
        if current_time - scan_data.get('started_at', 0) > max_age:
            scans_to_remove.append(scan_id)

    for scan_id in scans_to_remove:
        # Clean up PDF file
        pdf_path = f"/tmp/netsereno_{scan_id}.pdf"
        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except Exception:
                pass

        # Remove from active scans
        del active_scans[scan_id]
        logger.info(f"Cleaned up old scan: {scan_id}")


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    logger.info(f"Starting NetSereno Enterprise Scanner on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
