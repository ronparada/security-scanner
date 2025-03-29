from flask import Flask, render_template_string, request
import requests
import socket
import ssl
import dns.resolver
import re
from datetime import datetime
import concurrent.futures
import json

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Security Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .results {
            margin-top: 20px;
            white-space: pre-wrap;
            font-family: monospace;
        }
        .error {
            color: red;
        }
        .success {
            color: green;
        }
        .warning {
            color: orange;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .section-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced Security Scanner</h1>
        <form method="POST">
            <div class="form-group">
                <label for="target">Target Domain:</label>
                <input type="text" id="target" name="target" placeholder="example.com" required>
            </div>
            <div class="form-group">
                <label for="scan_type">Scan Type:</label>
                <select id="scan_type" name="scan_type">
                    <option value="ssl">SSL Check</option>
                    <option value="headers">Security Headers</option>
                    <option value="ports">Port Check</option>
                    <option value="subdomains">Subdomain Enumeration</option>
                    <option value="directories">Directory Scanning</option>
                    <option value="tech">Technology Stack</option>
                    <option value="email">Email Security</option>
                    <option value="all">Full Scan</option>
                </select>
            </div>
            <button type="submit">Start Scan</button>
        </form>
        {% if results %}
        <div class="results">
            {{ results }}
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

def check_ssl(domain):
    """Check SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
                
                results = []
                results.append("✅ SSL Certificate Status: Valid")
                results.append(f"📅 Expires: {expiry.strftime('%Y-%m-%d')} ({days_left} days left)")
                results.append(f"🔒 Issuer: {cert['issuer'][0][0][1]}")
                
                # Check for weak cipher suites
                cipher = ssock.cipher()
                if cipher[2] < 128:
                    results.append("⚠️ Warning: Weak cipher suite detected")
                
                return "\n".join(results)
    except Exception as e:
        return f"❌ SSL Error: {str(e)}"

def check_headers(url):
    """Check HTTP security headers"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(url, verify=False, timeout=5)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'X-Frame-Options': 'Clickjacking protection not enabled',
            'X-Content-Type-Options': 'MIME type protection not enabled',
            'X-XSS-Protection': 'XSS protection not enabled',
            'Content-Security-Policy': 'CSP not enabled',
            'Referrer-Policy': 'Referrer policy not set',
            'Permissions-Policy': 'Permissions policy not set'
        }
        
        results = []
        for header, message in security_headers.items():
            if header not in headers:
                results.append(f"⚠️ {message}")
            else:
                results.append(f"✅ {header}: {headers[header]}")
        
        # Check for server information disclosure
        if 'Server' in headers:
            results.append(f"ℹ️ Server: {headers['Server']}")
        
        return "\n".join(results)
    except Exception as e:
        return f"❌ Header Check Error: {str(e)}"

def check_ports(domain):
    """Check common ports"""
    try:
        common_ports = [80, 443, 22, 21, 25, 3306, 8080, 8443, 3389, 1433, 5432]
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(check_port, domain, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    results.append(f"❌ Error checking port {port}: {str(e)}")
        
        return "\n".join(results) if results else "No open ports found"
    except Exception as e:
        return f"❌ Port Check Error: {str(e)}"

def check_port(domain, port):
    """Check if a specific port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            service = get_service_banner(sock, port)
            return f"🔓 Port {port}: Open - {service}"
        sock.close()
        return None
    except:
        return None

def get_service_banner(sock, port):
    """Get service banner from open port"""
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        return banner.split('\n')[0] if banner else "Unknown Service"
    except:
        return "Unknown Service"

def enumerate_subdomains(domain):
    """Enumerate subdomains using DNS queries"""
    try:
        results = []
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging', 'api']
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                results.append(f"✅ Found subdomain: {full_domain}")
            except:
                continue
        
        return "\n".join(results) if results else "No subdomains found"
    except Exception as e:
        return f"❌ Subdomain Enumeration Error: {str(e)}"

def scan_directories(url):
    """Scan for common directories"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        common_dirs = [
            '/admin', '/login', '/wp-admin', '/phpinfo.php',
            '/robots.txt', '/sitemap.xml', '/.git', '/.env',
            '/api', '/backup', '/config', '/db'
        ]
        
        results = []
        for directory in common_dirs:
            try:
                response = requests.get(url + directory, verify=False, timeout=2)
                if response.status_code in [200, 301, 302]:
                    results.append(f"🔍 Found directory: {directory} (Status: {response.status_code})")
            except:
                continue
        
        return "\n".join(results) if results else "No sensitive directories found"
    except Exception as e:
        return f"❌ Directory Scanning Error: {str(e)}"

def detect_technology(url):
    """Detect technology stack"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(url, verify=False, timeout=5)
        headers = response.headers
        html = response.text
        
        results = []
        
        # Check server technology
        if 'Server' in headers:
            results.append(f"🖥️ Server: {headers['Server']}")
        
        # Check for common frameworks
        frameworks = {
            'Django': 'csrfmiddlewaretoken',
            'Laravel': 'laravel_session',
            'WordPress': 'wp-content',
            'React': 'react',
            'Angular': 'ng-',
            'Vue': 'vue'
        }
        
        for framework, indicator in frameworks.items():
            if indicator in html:
                results.append(f"⚙️ Framework: {framework}")
        
        # Check for common CMS
        cms = {
            'WordPress': 'wp-content',
            'Drupal': 'drupal.js',
            'Joomla': 'joomla.javascript',
            'Magento': 'Mage.Cookies'
        }
        
        for cms_name, indicator in cms.items():
            if indicator in html:
                results.append(f"📝 CMS: {cms_name}")
        
        return "\n".join(results) if results else "No technology stack information found"
    except Exception as e:
        return f"❌ Technology Detection Error: {str(e)}"

def check_email_security(domain):
    """Check email security settings"""
    try:
        results = []
        
        # Check SPF record
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                if 'v=spf1' in str(record):
                    results.append(f"✅ SPF Record: {record}")
                    break
            else:
                results.append("⚠️ No SPF record found")
        except:
            results.append("⚠️ No SPF record found")
        
        # Check DMARC record
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    results.append(f"✅ DMARC Record: {record}")
                    break
            else:
                results.append("⚠️ No DMARC record found")
        except:
            results.append("⚠️ No DMARC record found")
        
        # Check DKIM (common selector)
        try:
            dkim_records = dns.resolver.resolve(f'google._domainkey.{domain}', 'TXT')
            results.append(f"✅ DKIM Record: {dkim_records[0]}")
        except:
            results.append("⚠️ No DKIM record found")
        
        return "\n".join(results)
    except Exception as e:
        return f"❌ Email Security Check Error: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        target = request.form['target']
        scan_type = request.form['scan_type']
        
        results = []
        results.append(f"🎯 Target: {target}")
        results.append(f"⏰ Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if scan_type in ['ssl', 'all']:
            results.append("\n=== SSL Certificate Information ===")
            results.append(check_ssl(target))
        
        if scan_type in ['headers', 'all']:
            results.append("\n=== Security Headers ===")
            results.append(check_headers(target))
        
        if scan_type in ['ports', 'all']:
            results.append("\n=== Port Information ===")
            results.append(check_ports(target))
        
        if scan_type in ['subdomains', 'all']:
            results.append("\n=== Subdomain Enumeration ===")
            results.append(enumerate_subdomains(target))
        
        if scan_type in ['directories', 'all']:
            results.append("\n=== Directory Scanning ===")
            results.append(scan_directories(target))
        
        if scan_type in ['tech', 'all']:
            results.append("\n=== Technology Stack Detection ===")
            results.append(detect_technology(target))
        
        if scan_type in ['email', 'all']:
            results.append("\n=== Email Security ===")
            results.append(check_email_security(target))
        
        results = "\n".join(results)
    
    return render_template_string(HTML_TEMPLATE, results=results)

if __name__ == '__main__':
    app.run(debug=True) 