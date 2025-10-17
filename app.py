from flask import Flask, render_template, request, jsonify, send_file
from scanner import OWASPScanner
import os
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netsereno-security-2025'

# Store active scans
active_scans = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({'error': 'URL requerida'}), 400
    
    # Create scanner
    scanner = OWASPScanner(target_url)
    scan_id = scanner.scan_id
    
    # Store scanner
    active_scans[scan_id] = scanner
    
    # Start scan in background
    def run_scan():
        scanner.run_scan()
        # Generate PDF
        pdf_path = f"/tmp/netsereno_{scan_id}.pdf"
        scanner.generate_pdf_report(pdf_path)
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Escaneo iniciado'
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def scan_status(scan_id):
    scanner = active_scans.get(scan_id)
    
    if not scanner:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    return jsonify({
        'progress': scanner.progress,
        'status': scanner.status,
        'completed': scanner.progress >= 100
    })

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def scan_results(scan_id):
    scanner = active_scans.get(scan_id)
    
    if not scanner:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    if scanner.progress < 100:
        return jsonify({'error': 'Escaneo en progreso'}), 400
    
    return jsonify({
        'results': scanner.results,
        'summary': scanner.get_summary(),
        'target': scanner.target_url,
        'ip': scanner.ip,
        'scan_time': scanner.scan_start.strftime('%d/%m/%Y %H:%M:%S')
    })

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def download_report(scan_id):
    pdf_path = f"/tmp/netsereno_{scan_id}.pdf"
    
    if not os.path.exists(pdf_path):
        return jsonify({'error': 'Reporte no encontrado'}), 404
    
    return send_file(pdf_path, as_attachment=True, download_name=f'netsereno_report_{scan_id}.pdf')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
