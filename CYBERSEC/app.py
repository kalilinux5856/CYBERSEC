from flask import Flask, request, jsonify
import requests
import os
from datetime import datetime
import sqlite3
import tldextract
from urllib.parse import urlparse
import re
import socket
from urllib3.exceptions import LocationParseError
import sys

app = Flask(__name__)
first_run = True

# Constants for suspicious patterns
SUSPICIOUS_KEYWORDS = {
    'high_risk': [
        'account', 'banking', 'confirm', 'login', 'password', 'secure', 'update',
        'verify', 'wallet', 'alert', 'limited', 'security', 'signin', 'support'
    ],
    'medium_risk': [
        'bonus', 'free', 'prize', 'winner', 'won', 'lucky', 'gift', 'offer',
        'special', 'payment', 'money', 'credit', 'debit', 'transfer'
    ]
}

SUSPICIOUS_TLD = {
    'high_risk': ['.xyz', '.top', '.work', '.click', '.loan', '.win', '.link'],
    'medium_risk': ['.info', '.site', '.online', '.space', '.website', '.tech']
}

def is_valid_domain(domain):
    """Check if domain exists and is reachable"""
    try:
        # Try to resolve the domain
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def analyze_url_security(url):
    """
    Analyze URL for potential security threats
    Returns a dictionary with risk assessment
    """
    try:
        # Basic URL parsing
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        risk_factors = []
        risk_score = 0

        # Check if domain is empty
        if not domain:
            return {
                'risk_level': 'High Risk',
                'risk_score': 10,
                'risk_factors': ['Invalid URL format - No domain specified'],
                'details': {'url': url, 'error': 'Invalid URL format'}
            }

        # Check if domain exists
        if not is_valid_domain(domain):
            return {
                'risk_level': 'High Risk',
                'risk_score': 10,
                'risk_factors': ['Non-existent or unreachable domain'],
                'details': {'url': url, 'error': 'Domain does not exist'}
            }

        # Check for valid TLD
        domain_info = tldextract.extract(url)
        if not domain_info.suffix:
            return {
                'risk_level': 'High Risk',
                'risk_score': 10,
                'risk_factors': ['Invalid or missing top-level domain'],
                'details': {'url': url, 'error': 'Invalid TLD'}
            }

        # Continue with existing security checks
        if parsed_url.scheme != 'https':
            risk_factors.append("No HTTPS connection")
            risk_score += 1

        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLD['high_risk']:
            if domain.endswith(tld):
                risk_factors.append(f"High-risk top-level domain ({tld})")
                risk_score += 3
                break
        for tld in SUSPICIOUS_TLD['medium_risk']:
            if domain.endswith(tld):
                risk_factors.append(f"Medium-risk top-level domain ({tld})")
                risk_score += 1
                break

        # Check for suspicious keywords
        for keyword in SUSPICIOUS_KEYWORDS['high_risk']:
            if keyword in domain or keyword in path:
                risk_factors.append(f"Contains high-risk keyword: {keyword}")
                risk_score += 2
        for keyword in SUSPICIOUS_KEYWORDS['medium_risk']:
            if keyword in domain or keyword in path:
                risk_factors.append(f"Contains medium-risk keyword: {keyword}")
                risk_score += 1

        # Check for unusual characters in domain
        if re.search(r'[^a-zA-Z0-9\-\.]', domain):
            risk_factors.append("Domain contains unusual characters")
            risk_score += 2

        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_factors.append("Excessive number of subdomains")
            risk_score += 1

        # Check for long domain name (potential phishing)
        if len(domain) > 50:
            risk_factors.append("Unusually long domain name")
            risk_score += 1

        # Try to make an HTTP HEAD request to check if the site exists
        try:
            response = requests.head(url if parsed_url.scheme else f"http://{url}", 
                                  timeout=3, 
                                  allow_redirects=True)
            if response.status_code >= 400:
                risk_factors.append("URL returns an error status code")
                risk_score += 2
        except requests.RequestException:
            risk_factors.append("Unable to connect to URL")
            risk_score += 2

        # Determine risk level based on score
        if risk_score == 0:
            risk_level = "Safe"
        elif risk_score <= 2:
            risk_level = "Low Risk"
        elif risk_score <= 4:
            risk_level = "Medium Risk"
        else:
            risk_level = "High Risk"

        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'details': {
                'url': url,
                'domain': domain,
                'scheme': parsed_url.scheme,
                'path': path,
                'analysis': {
                    'has_https': parsed_url.scheme == 'https',
                    'subdomain_count': subdomain_count,
                    'domain_length': len(domain),
                    'is_reachable': True
                }
            }
        }

    except Exception as e:
        return {
            'risk_level': 'High Risk',
            'risk_score': 10,
            'risk_factors': [f'Error analyzing URL: {str(e)}'],
            'details': {'url': url, 'error': str(e)}
        }

def get_db_connection():
    conn = sqlite3.connect('url_history.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")
        raise

def reset_db():
    try:
        if os.path.exists('url_history.db'):
            os.remove('url_history.db')
            print("Existing database deleted")
        init_db()
        print("Database reset successfully")
    except Exception as e:
        print(f"Error resetting database: {e}")

def save_scan_history(url, scan_result):
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO scan_history (url, risk_level, timestamp, details)
            VALUES (?, ?, ?, ?)
        ''', (
            url,
            scan_result.get('risk_level', 'Unknown'),
            datetime.now().isoformat(),
            str(scan_result)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving to database: {e}")
        raise

@app.route('/', methods=['GET'])
def home():
    global first_run
    if first_run:
        reset_db()
        first_run = False
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>URL Security Scanner</title>
        <style>
            :root {
                --primary-gradient: linear-gradient(135deg, #1a5d1a, #2e7d32);
                --primary-color: #1a5d1a;
                --primary-hover: #164816;
                --background-color: #f0f2f5;
                --container-bg: #ffffff;
                --shadow-color: rgba(0, 0, 0, 0.1);
                --border-radius: 12px;
            }
            
            body { 
                font-family: 'Segoe UI', Arial, sans-serif;
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 20px;
                background-color: var(--background-color);
                color: #2c3e50;
            }
            
            .container { 
                margin-top: 20px;
                background-color: var(--container-bg);
                padding: 30px;
                border-radius: var(--border-radius);
                box-shadow: 0 4px 6px var(--shadow-color);
            }
            
            h1 {
                background: var(--primary-gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 30px;
                font-size: 2.5em;
                text-align: center;
                font-weight: 700;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
            
            .scan-container {
                display: flex;
                gap: 15px;
                margin-bottom: 30px;
                background: #f8f9fa;
                padding: 20px;
                border-radius: var(--border-radius);
                box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
            }
            
            input[type="text"] { 
                flex: 1;
                padding: 12px 20px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 15px;
                transition: all 0.3s ease;
                color: #2c3e50;
                font-weight: 500;
            }
            
            input[type="text"]:focus {
                border-color: #1a5d1a;
                outline: none;
                box-shadow: 0 0 0 3px rgba(26, 93, 26, 0.1);
            }
            
            button { 
                background: var(--primary-gradient);
                color: white;
                padding: 12px 25px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 15px;
                font-weight: 600;
                min-width: 120px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }
            
            button:active {
                transform: translateY(0);
            }
            
            #result { 
                margin: 20px 0;
                padding: 20px;
                border-radius: var(--border-radius);
                background: #f8f9fa;
            }
            
            .error { 
                color: #dc2626; 
                background-color: #fee2e2;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #dc2626;
            }
            
            .safe { 
                background: linear-gradient(135deg, #f0fdf4, #dcfce7);
                color: #166534;
                padding: 20px;
                border-radius: 8px;
                border-left: 4px solid #166534;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            .high-risk { 
                background: linear-gradient(135deg, #fef2f2, #fee2e2);
                color: #991b1b;
                padding: 20px;
                border-radius: 8px;
                border-left: 4px solid #991b1b;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            .medium-risk { 
                background: linear-gradient(135deg, #fff7ed, #ffedd5);
                color: #9a3412;
                padding: 20px;
                border-radius: 8px;
                border-left: 4px solid #9a3412;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            .section-header {
                background: linear-gradient(135deg, #2c5282, #1a5d1a);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin: 40px 0 20px 0;
                font-size: 1.8em;
                font-weight: 600;
                border-bottom: 3px solid #1a5d1a;
                padding-bottom: 10px;
            }
            
            .history-table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-top: 20px;
                background: white;
                border-radius: var(--border-radius);
                overflow: hidden;
                box-shadow: 0 4px 6px var(--shadow-color);
            }
            
            .history-table th {
                background: var(--primary-gradient);
                color: white;
                padding: 15px;
                text-align: left;
                font-weight: 600;
                font-size: 15px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .history-table td {
                padding: 12px 15px;
                border-bottom: 1px solid #e5e7eb;
                vertical-align: middle;
            }
            
            .history-table tr:last-child td {
                border-bottom: none;
            }
            
            .history-table tr:hover td {
                background-color: #f8f9fa;
            }
            
            .risk-badge {
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
                display: inline-block;
                text-align: center;
                min-width: 120px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            
            .risk-badge-safe {
                background: linear-gradient(135deg, #dcfce7, #bbf7d0);
                color: #166534;
                border: none;
            }
            
            .risk-badge-low {
                background: linear-gradient(135deg, #dbeafe, #bfdbfe);
                color: #1e40af;
                border: none;
            }
            
            .risk-badge-medium {
                background: linear-gradient(135deg, #fff7ed, #fed7aa);
                color: #9a3412;
                border: none;
            }
            
            .risk-badge-high {
                background: linear-gradient(135deg, #fee2e2, #fecaca);
                color: #991b1b;
                border: none;
            }
            
            .url-link {
                background: linear-gradient(135deg, #1a5d1a, #2e7d32);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                text-decoration: none;
                transition: all 0.2s ease;
                display: block;
                max-width: 500px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-weight: 500;
            }
            
            .url-link:hover {
                opacity: 0.8;
                text-decoration: underline;
            }
            
            @media (max-width: 768px) {
                .scan-container {
                    flex-direction: column;
                }
                
                button {
                    width: 100%;
                }
                
                .container {
                    padding: 20px;
                }
            }

            /* Add result details styling */
            .result-details {
                margin-top: 15px;
                padding: 15px;
                background: rgba(255, 255, 255, 0.7);
                border-radius: 8px;
            }

            .result-details h3 {
                color: #2c3e50;
                margin-bottom: 15px;
                font-size: 1.3em;
            }

            .result-details ul {
                list-style-type: none;
                padding-left: 0;
            }

            .result-details li {
                padding: 8px 0;
                border-bottom: 1px solid rgba(0,0,0,0.1);
                color: #4a5568;
            }

            .result-details li:last-child {
                border-bottom: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>URL Security Scanner</h1>
            
            <div class="scan-container">
                <input type="text" id="urlInput" placeholder="Enter URL to scan (e.g., example.com)">
                <button id="scanButton" onclick="scanURL()">Scan URL</button>
            </div>
            
            <div id="result"></div>
            
            <h2 class="section-header">Recent Scans</h2>
            <div class="table-container">
                <table class="history-table">
                    <thead>
                        <tr>
                            <th style="width: 50%">URL</th>
                            <th style="width: 25%">Risk Level</th>
                            <th style="width: 25%">Scan Time</th>
                        </tr>
                    </thead>
                    <tbody id="historyBody">
                        <tr>
                            <td colspan="3" style="text-align: center;">Loading scan history...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <script>
        async function scanURL() {
            const urlInput = document.getElementById('urlInput');
            const resultDiv = document.getElementById('result');
            const url = urlInput.value.trim();
            
            if (!url) {
                resultDiv.innerHTML = '<p class="error">Please enter a URL</p>';
                return;
            }

            resultDiv.innerHTML = '<p>Scanning URL...</p>';
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({url: url})
                });
                
                const data = await response.json();
                
                if (data.error) {
                    resultDiv.innerHTML = `<p class="error">Error: ${data.error}</p>`;
                } else {
                    resultDiv.innerHTML = `
                        <div class="${data.risk_level.toLowerCase().replace(' ', '-')}">
                            <h3>Scan Results</h3>
                            <p>Risk Level: ${data.risk_level}</p>
                            <p>Risk Score: ${data.risk_score}</p>
                            ${data.risk_factors.length > 0 ? `
                                <p>Risk Factors:</p>
                                <ul>
                                    ${data.risk_factors.map(factor => `<li>${factor}</li>`).join('')}
                                </ul>
                            ` : '<p>No risk factors detected</p>'}
                        </div>
                    `;
                    
                    loadHistory();
                }
            } catch (error) {
                resultDiv.innerHTML = `<p class="error">Error scanning URL: ${error.message}</p>`;
            }
        }

        async function loadHistory() {
            const historyBody = document.getElementById('historyBody');
            try {
                const response = await fetch('/history');
                const data = await response.json();
                
                if (!data || data.length === 0) {
                    historyBody.innerHTML = `
                        <tr>
                            <td colspan="3" style="text-align: center;">No scan history available</td>
                        </tr>
                    `;
                    return;
                }
                
                historyBody.innerHTML = data.map(scan => `
                    <tr>
                        <td>
                            <a href="${scan.url}" target="_blank" class="url-link" title="${scan.url}">
                                ${scan.url}
                            </a>
                        </td>
                        <td>
                            <span class="risk-badge ${getRiskBadgeClass(scan.risk_level)}">
                                ${scan.risk_level}
                            </span>
                        </td>
                        <td>${formatDateTime(scan.timestamp)}</td>
                    </tr>
                `).join('');
            } catch (error) {
                historyBody.innerHTML = `
                    <tr>
                        <td colspan="3" style="text-align: center; color: red;">
                            Error loading scan history: ${error.message}
                        </td>
                    </tr>
                `;
            }
        }

        function getRiskBadgeClass(riskLevel) {
            switch(riskLevel.toLowerCase()) {
                case 'safe': return 'risk-badge-safe';
                case 'low risk': return 'risk-badge-low';
                case 'medium risk': return 'risk-badge-medium';
                case 'high risk': return 'risk-badge-high';
                default: return 'risk-badge-medium';
            }
        }

        function formatDateTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleString();
        }

        // Load history when page loads
        loadHistory();
        </script>
    </body>
    </html>
    '''

@app.route('/scan', methods=['POST'])
def scan_url():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        analysis_result = analyze_url_security(url)
        save_scan_history(url, analysis_result)
        
        return jsonify(analysis_result)

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/history', methods=['GET'])
def get_history():
    try:
        conn = get_db_connection()
        history = conn.execute('SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 10').fetchall()
        conn.close()
        
        return jsonify([{
            'url': h['url'],
            'risk_level': h['risk_level'],
            'timestamp': h['timestamp']
        } for h in history])
    except Exception as e:
        return jsonify([])

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)