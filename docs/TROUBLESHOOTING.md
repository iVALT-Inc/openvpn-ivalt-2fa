# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the OpenVPN iVALT 2FA Integration.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Common Issues](#common-issues)
- [Error Messages](#error-messages)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [Debugging Tools](#debugging-tools)
- [Advanced Troubleshooting](#advanced-troubleshooting)

## Quick Diagnostics

### Health Check Script

Create a diagnostic script to quickly identify common issues:

```python
#!/usr/bin/env python3
"""Quick diagnostic script for OpenVPN iVALT 2FA Integration."""

import os
import sys
import requests
import subprocess
from pathlib import Path

def check_python_version():
    """Check Python version compatibility."""
    version = sys.version_info
    if version.major == 3 and version.minor >= 7:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.7+")
        return False

def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import requests
        print(f"✅ requests {requests.__version__} - Installed")
        return True
    except ImportError:
        print("❌ requests - Not installed")
        return False

def check_script_permissions():
    """Check script file permissions."""
    script_path = Path("main.py")
    if script_path.exists():
        stat = script_path.stat()
        if stat.st_mode & 0o111:  # Check if executable
            print("✅ main.py - Executable")
            return True
        else:
            print("❌ main.py - Not executable")
            return False
    else:
        print("❌ main.py - Not found")
        return False

def check_network_connectivity():
    """Check network connectivity to iVALT API."""
    try:
        response = requests.get("https://api.ivalt.com", timeout=10)
        print("✅ iVALT API - Reachable")
        return True
    except requests.RequestException as e:
        print(f"❌ iVALT API - Unreachable: {e}")
        return False

def check_api_key():
    """Check if API key is configured."""
    try:
        with open("main.py", "r") as f:
            content = f.read()
            if "your_ivalt_secret_key_here" in content:
                print("❌ API Key - Not configured (placeholder found)")
                return False
            elif "IVALT_SECRET_KEY" in content:
                print("✅ API Key - Configured")
                return True
            else:
                print("❌ API Key - Not found")
                return False
    except FileNotFoundError:
        print("❌ main.py - File not found")
        return False

def run_diagnostics():
    """Run all diagnostic checks."""
    print("🔍 OpenVPN iVALT 2FA Integration Diagnostics")
    print("=" * 50)

    checks = [
        check_python_version,
        check_dependencies,
        check_script_permissions,
        check_network_connectivity,
        check_api_key
    ]

    results = []
    for check in checks:
        results.append(check())

    print("\n📊 Summary:")
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("🎉 All checks passed! Your setup looks good.")
    else:
        print("⚠️  Some issues found. Please review the errors above.")

    return passed == total

if __name__ == "__main__":
    run_diagnostics()
```

### Quick Fixes

```bash
# Make script executable
chmod +x main.py

# Install missing dependencies
pip install requests

# Test API connectivity
curl -I https://api.ivalt.com

# Check OpenVPN service status
systemctl status openvpnas

# Restart OpenVPN services
systemctl restart openvpnas
```

## Common Issues

### Issue 1: Script Not Executing

#### Symptoms

- VPN authentication fails
- No logs from post-authentication script
- OpenVPN shows authentication error

#### Causes

- Incorrect script path in OpenVPN configuration
- Missing execute permissions
- Python not found in PATH
- Script syntax errors

#### Solutions

**Check Script Path**

```bash
# Verify script exists and is accessible
ls -la /path/to/main.py

# Test script execution manually
python3 /path/to/main.py
```

**Fix Permissions**

```bash
# Make script executable
chmod +x main.py

# Set proper ownership
chown openvpn:openvpn main.py
```

**Verify Python Path**

```bash
# Check Python installation
which python3
python3 --version

# Update script shebang if needed
sed -i '1s|^|#!/usr/bin/env python3\n|' main.py
```

**Test Script Syntax**

```bash
# Check for syntax errors
python3 -m py_compile main.py

# Run with verbose output
python3 -v main.py
```

### Issue 2: API Connection Failures

#### Symptoms

- Network timeout errors
- SSL certificate errors
- DNS resolution failures
- Connection refused errors

#### Causes

- Firewall blocking outbound connections
- Network connectivity issues
- DNS resolution problems
- SSL certificate validation failures

#### Solutions

**Test Network Connectivity**

```bash
# Test basic connectivity
ping api.ivalt.com

# Test HTTPS connectivity
curl -I https://api.ivalt.com

# Test with verbose output
curl -v https://api.ivalt.com
```

**Check Firewall Rules**

```bash
# Check firewall status
sudo ufw status

# Allow outbound HTTPS
sudo ufw allow out 443

# Check iptables rules
sudo iptables -L OUTPUT
```

**Verify DNS Resolution**

```bash
# Test DNS resolution
nslookup api.ivalt.com

# Check DNS configuration
cat /etc/resolv.conf
```

**Test SSL Certificate**

```bash
# Test SSL certificate
openssl s_client -connect api.ivalt.com:443 -servername api.ivalt.com

# Check certificate validity
echo | openssl s_client -connect api.ivalt.com:443 2>/dev/null | openssl x509 -noout -dates
```

### Issue 3: Authentication Failures

#### Symptoms

- Users receive "AUTHENTICATION_FAILED" error
- iVALT app doesn't receive notification
- Geofencing errors
- Timezone validation failures

#### Causes

- Invalid API key
- User not found in iVALT system
- Mobile number not configured
- Geofencing rules too restrictive
- Timezone mismatch

#### Solutions

**Verify API Key**

```python
# Test API key validity
import requests

def test_api_key(api_key):
    url = "https://api.ivalt.com/get-user-by-email"
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json"
    }
    payload = {"email": "test@example.com"}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code != 401
    except Exception as e:
        print(f"Error: {e}")
        return False

# Test your API key
test_api_key("your_api_key_here")
```

**Check User Configuration**

```python
# Verify user exists in iVALT
def check_user(email):
    url = "https://api.ivalt.com/get-user-by-email"
    headers = {
        "x-api-key": "your_api_key_here",
        "Content-Type": "application/json"
    }
    payload = {"email": email}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            mobile = data['data']['details']['mobile_with_country_code']
            print(f"User found: {email}")
            print(f"Mobile: {mobile}")
            return True
        else:
            print(f"User not found: {email}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# Check specific user
check_user("user@example.com")
```

**Test Mobile Notification**

```python
# Test mobile notification
def test_mobile_notification(mobile):
    url = "https://api.ivalt.com/biometric-auth-request"
    headers = {
        "x-api-key": "your_api_key_here",
        "Content-Type": "application/json"
    }
    payload = {"mobile": mobile}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
            print("Notification sent successfully")
            return True
        else:
            print(f"Notification failed: {response.text}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

# Test with user's mobile number
test_mobile_notification("+1234567890")
```

## Error Messages

### Common Error Messages

#### "AUTHENTICATION_FAILED"

- **Cause**: General authentication failure
- **Solution**: Check API key, user configuration, and network connectivity

#### "INVALID_TIMEZONE"

- **Cause**: User's timezone doesn't match security requirements
- **Solution**: Adjust timezone settings in iVALT or user's device

#### "INVALID_GEOFENCE"

- **Cause**: User's location is outside allowed geofence boundaries
- **Solution**: Check geofencing rules or user's location

#### "USER_NOT_FOUND"

- **Cause**: User email not found in iVALT system
- **Solution**: Verify user exists in iVALT and email is correct

#### "API_KEY_INVALID"

- **Cause**: Invalid or expired API key
- **Solution**: Verify API key and contact iVALT support if needed

### Error Message Debugging

```python
# Enhanced error handling
def debug_error(response):
    """Debug API error responses."""
    try:
        error_data = response.json()
        error_code = error_data.get('error', {}).get('code', 'UNKNOWN')
        error_detail = error_data.get('error', {}).get('detail', 'No details')

        print(f"Error Code: {error_code}")
        print(f"Error Detail: {error_detail}")
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")

        # Provide specific guidance
        if error_code == 'USER_NOT_FOUND':
            print("💡 Solution: Verify user exists in iVALT system")
        elif error_code == 'INVALID_TIMEZONE':
            print("💡 Solution: Check timezone settings")
        elif error_code == 'INVALID_GEOFENCE':
            print("💡 Solution: Check geofencing rules")
        elif error_code == 'API_KEY_INVALID':
            print("💡 Solution: Verify API key validity")

    except ValueError:
        print(f"Raw response: {response.text}")
```

## Performance Issues

### Issue 1: Slow Authentication

#### Symptoms

- Long delays during authentication
- Timeout errors
- Poor user experience

#### Causes

- Network latency
- API response delays
- Inefficient retry logic
- Resource constraints

#### Solutions

**Optimize Timeout Settings**

```python
# Reduce timeout values
while (time.time() - start_time) < 30:  # Reduce from 60 to 30 seconds
    time.sleep(2)  # Reduce from 5 to 2 seconds
```

**Implement Connection Pooling**

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session():
    """Create optimized HTTP session."""
    session = requests.Session()

    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    # Configure adapter
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session

# Use session for all requests
session = create_session()
```

**Monitor Performance**

```python
import time
import logging

def monitor_performance(func):
    """Decorator to monitor function performance."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        duration = end_time - start_time
        logging.info(f"{func.__name__} took {duration:.2f} seconds")

        return result
    return wrapper

@monitor_performance
def ivalt_auth_request_sent(mobile: str) -> bool:
    # Your existing function
    pass
```

### Issue 2: High Resource Usage

#### Symptoms

- High CPU usage
- Memory leaks
- System slowdown

#### Causes

- Inefficient API calls
- Memory leaks
- Resource-intensive operations
- Poor error handling

#### Solutions

**Optimize API Calls**

```python
# Cache user data to reduce API calls
user_cache = {}

def get_cached_user(email):
    """Get user data from cache or API."""
    if email in user_cache:
        return user_cache[email]

    # Fetch from API
    success, mobile = ivalt_get_mobile_by_email(email)
    if success:
        user_cache[email] = mobile
        return mobile

    return None
```

**Implement Resource Monitoring**

```python
import psutil
import logging

def monitor_resources():
    """Monitor system resource usage."""
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent

    if cpu_percent > 80:
        logging.warning(f"High CPU usage: {cpu_percent}%")

    if memory_percent > 80:
        logging.warning(f"High memory usage: {memory_percent}%")
```

## Security Issues

### Issue 1: API Key Exposure

#### Symptoms

- API key visible in logs
- Unauthorized API usage
- Security warnings

#### Causes

- Logging API keys
- Hardcoded keys in scripts
- Insecure key storage
- Key sharing

#### Solutions

**Secure Key Storage**

```python
import os
from cryptography.fernet import Fernet

def encrypt_api_key(key: str) -> bytes:
    """Encrypt API key for secure storage."""
    fernet = Fernet(os.environ.get('ENCRYPTION_KEY'))
    return fernet.encrypt(key.encode())

def decrypt_api_key(encrypted_key: bytes) -> str:
    """Decrypt API key for use."""
    fernet = Fernet(os.environ.get('ENCRYPTION_KEY'))
    return fernet.decrypt(encrypted_key).decode()

# Store encrypted key
encrypted_key = encrypt_api_key("your_api_key_here")
with open("api_key.enc", "wb") as f:
    f.write(encrypted_key)
```

**Environment Variable Usage**

```python
import os

# Use environment variable
IVALT_SECRET_KEY = os.environ.get('IVALT_SECRET_KEY')

if not IVALT_SECRET_KEY:
    raise ValueError("IVALT_SECRET_KEY environment variable not set")
```

**Secure Logging**

```python
import logging
import re

class SecureFormatter(logging.Formatter):
    """Formatter that masks sensitive information."""

    def format(self, record):
        message = super().format(record)
        # Mask API keys
        message = re.sub(r'x-api-key: [^\s]+', 'x-api-key: [MASKED]', message)
        return message

# Configure secure logging
handler = logging.StreamHandler()
handler.setFormatter(SecureFormatter())
logger = logging.getLogger()
logger.addHandler(handler)
```

### Issue 2: Network Security

#### Symptoms

- SSL certificate warnings
- Man-in-the-middle attacks
- Data interception
- Unencrypted communication

#### Causes

- Weak SSL configuration
- Certificate validation disabled
- Insecure network protocols
- Missing security headers

#### Solutions

**SSL Certificate Validation**

```python
import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class SSLAdapter(HTTPAdapter):
    """Adapter with custom SSL configuration."""

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Use secure adapter
session = requests.Session()
session.mount('https://', SSLAdapter())
```

**Security Headers**

```python
def add_security_headers(headers):
    """Add security headers to requests."""
    headers.update({
        'User-Agent': 'OpenVPN-iVALT-2FA/1.0',
        'X-Requested-With': 'XMLHttpRequest',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    })
    return headers
```

## Debugging Tools

### Logging Configuration

```python
import logging
import sys
from datetime import datetime

def setup_debug_logging():
    """Setup comprehensive debug logging."""

    # Create logger
    logger = logging.getLogger('ivalt_2fa_debug')
    logger.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # File handler
    file_handler = logging.FileHandler('debug.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

# Use debug logger
debug_logger = setup_debug_logging()
```

### API Request Debugging

```python
import requests
import json
from datetime import datetime

def debug_api_request(url, headers, payload):
    """Debug API requests with detailed logging."""

    debug_logger.info(f"Making API request to: {url}")
    debug_logger.debug(f"Headers: {json.dumps(headers, indent=2)}")
    debug_logger.debug(f"Payload: {json.dumps(payload, indent=2)}")

    start_time = datetime.now()

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        debug_logger.info(f"Response received in {duration:.2f} seconds")
        debug_logger.info(f"Status Code: {response.status_code}")
        debug_logger.debug(f"Response Headers: {dict(response.headers)}")
        debug_logger.debug(f"Response Body: {response.text}")

        return response

    except requests.RequestException as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        debug_logger.error(f"Request failed after {duration:.2f} seconds: {e}")
        raise
```

### Performance Profiling

```python
import cProfile
import pstats
import io
from functools import wraps

def profile_function(func):
    """Decorator to profile function performance."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()

        result = func(*args, **kwargs)

        profiler.disable()

        # Save profile results
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats()

        debug_logger.debug(f"Profile for {func.__name__}:\n{s.getvalue()}")

        return result
    return wrapper

# Use profiling decorator
@profile_function
def ivalt_auth_request_sent(mobile: str) -> bool:
    # Your function
    pass
```

## Advanced Troubleshooting

### Network Packet Analysis

```bash
# Capture network traffic
sudo tcpdump -i any -w ivalt_traffic.pcap host api.ivalt.com

# Analyze captured packets
tcpdump -r ivalt_traffic.pcap -n

# Monitor real-time traffic
sudo tcpdump -i any host api.ivalt.com
```

### System Resource Monitoring

```bash
# Monitor system resources
htop

# Monitor network connections
netstat -tulpn | grep :443

# Monitor disk usage
df -h

# Monitor memory usage
free -h
```

### OpenVPN Access Server Logs

```bash
# Check OpenVPN Access Server logs
tail -f /var/log/openvpnas.log

# Filter authentication logs
grep "post_auth" /var/log/openvpnas.log

# Check error logs
grep "ERROR" /var/log/openvpnas.log

# Monitor real-time logs
journalctl -u openvpnas -f
```

### Custom Diagnostic Script

```python
#!/usr/bin/env python3
"""Comprehensive diagnostic script for OpenVPN iVALT 2FA Integration."""

import os
import sys
import json
import requests
import subprocess
import time
from pathlib import Path
from datetime import datetime

class IVALTDiagnostics:
    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()

    def log(self, message, level="INFO"):
        """Log diagnostic message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def check_system_info(self):
        """Check system information."""
        self.log("Checking system information...")

        try:
            # Python version
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            self.results['python_version'] = python_version

            # Operating system
            if os.name == 'posix':
                try:
                    result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
                    self.results['os_info'] = result.stdout.strip()
                except:
                    self.results['os_info'] = "Unknown POSIX system"
            else:
                self.results['os_info'] = f"Windows {os.name}"

            # Working directory
            self.results['working_directory'] = os.getcwd()

            self.log(f"Python version: {python_version}")
            self.log(f"OS: {self.results['os_info']}")
            self.log(f"Working directory: {self.results['working_directory']}")

        except Exception as e:
            self.log(f"Error checking system info: {e}", "ERROR")

    def check_dependencies(self):
        """Check Python dependencies."""
        self.log("Checking Python dependencies...")

        dependencies = ['requests']
        for dep in dependencies:
            try:
                module = __import__(dep)
                version = getattr(module, '__version__', 'Unknown')
                self.results[f'dep_{dep}'] = version
                self.log(f"✅ {dep}: {version}")
            except ImportError:
                self.results[f'dep_{dep}'] = "Not installed"
                self.log(f"❌ {dep}: Not installed", "ERROR")

    def check_script_file(self):
        """Check main script file."""
        self.log("Checking main script file...")

        script_path = Path("main.py")
        if script_path.exists():
            # Check permissions
            stat = script_path.stat()
            is_executable = stat.st_mode & 0o111
            self.results['script_exists'] = True
            self.results['script_executable'] = is_executable
            self.results['script_size'] = stat.st_size

            # Check for API key
            try:
                with open(script_path, 'r') as f:
                    content = f.read()
                    has_placeholder = "your_ivalt_secret_key_here" in content
                    has_api_key = "IVALT_SECRET_KEY" in content
                    self.results['script_has_placeholder'] = has_placeholder
                    self.results['script_has_api_key'] = has_api_key

                    if has_placeholder:
                        self.log("❌ API key placeholder found", "ERROR")
                    elif has_api_key:
                        self.log("✅ API key configuration found")
                    else:
                        self.log("⚠️ No API key configuration found", "WARNING")

            except Exception as e:
                self.log(f"Error reading script: {e}", "ERROR")
        else:
            self.results['script_exists'] = False
            self.log("❌ main.py not found", "ERROR")

    def check_network_connectivity(self):
        """Check network connectivity to iVALT API."""
        self.log("Checking network connectivity...")

        try:
            # Test basic connectivity
            response = requests.get("https://api.ivalt.com", timeout=10)
            self.results['api_reachable'] = True
            self.results['api_status_code'] = response.status_code
            self.log(f"✅ iVALT API reachable (Status: {response.status_code})")

            # Test DNS resolution
            import socket
            try:
                ip = socket.gethostbyname("api.ivalt.com")
                self.results['dns_resolution'] = ip
                self.log(f"✅ DNS resolution: api.ivalt.com -> {ip}")
            except socket.gaierror as e:
                self.results['dns_resolution'] = f"Failed: {e}"
                self.log(f"❌ DNS resolution failed: {e}", "ERROR")

        except requests.RequestException as e:
            self.results['api_reachable'] = False
            self.results['api_error'] = str(e)
            self.log(f"❌ iVALT API unreachable: {e}", "ERROR")

    def check_openvpn_service(self):
        """Check OpenVPN Access Server service status."""
        self.log("Checking OpenVPN Access Server service...")

        try:
            # Check if OpenVPN is running
            result = subprocess.run(['systemctl', 'is-active', 'openvpnas'],
                                  capture_output=True, text=True)
            is_active = result.stdout.strip() == 'active'
            self.results['openvpn_active'] = is_active

            if is_active:
                self.log("✅ OpenVPN Access Server is active")
            else:
                self.log("❌ OpenVPN Access Server is not active", "ERROR")

        except Exception as e:
            self.log(f"Error checking OpenVPN service: {e}", "ERROR")

    def run_api_test(self):
        """Run API functionality test."""
        self.log("Running API functionality test...")

        try:
            # This would require a valid API key
            # For now, just test the endpoint structure
            url = "https://api.ivalt.com/get-user-by-email"
            headers = {
                "Content-Type": "application/json"
            }
            payload = {"email": "test@example.com"}

            # Test without API key to see error response
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            self.results['api_test_status'] = response.status_code
            self.results['api_test_response'] = response.text[:200]  # First 200 chars

            if response.status_code == 401:
                self.log("✅ API endpoint responds (401 Unauthorized expected)")
            else:
                self.log(f"⚠️ Unexpected API response: {response.status_code}", "WARNING")

        except Exception as e:
            self.results['api_test_error'] = str(e)
            self.log(f"❌ API test failed: {e}", "ERROR")

    def generate_report(self):
        """Generate diagnostic report."""
        self.log("Generating diagnostic report...")

        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        report = {
            'timestamp': end_time.isoformat(),
            'duration_seconds': duration,
            'results': self.results,
            'summary': self.get_summary()
        }

        # Save report to file
        report_file = f"diagnostic_report_{end_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        self.log(f"Diagnostic report saved to: {report_file}")
        return report

    def get_summary(self):
        """Get diagnostic summary."""
        issues = []
        warnings = []

        # Check for critical issues
        if not self.results.get('script_exists', False):
            issues.append("Main script file not found")

        if self.results.get('script_has_placeholder', False):
            issues.append("API key placeholder not replaced")

        if not self.results.get('api_reachable', False):
            issues.append("iVALT API not reachable")

        if not self.results.get('openvpn_active', False):
            issues.append("OpenVPN Access Server not active")

        # Check for warnings
        if not self.results.get('script_executable', False):
            warnings.append("Script not executable")

        if not self.results.get('script_has_api_key', False):
            warnings.append("No API key configuration found")

        return {
            'critical_issues': issues,
            'warnings': warnings,
            'status': 'PASS' if not issues else 'FAIL'
        }

    def run_all_checks(self):
        """Run all diagnostic checks."""
        self.log("Starting comprehensive diagnostics...")

        self.check_system_info()
        self.check_dependencies()
        self.check_script_file()
        self.check_network_connectivity()
        self.check_openvpn_service()
        self.run_api_test()

        report = self.generate_report()

        # Print summary
        summary = report['summary']
        self.log("=" * 50)
        self.log("DIAGNOSTIC SUMMARY")
        self.log("=" * 50)

        if summary['status'] == 'PASS':
            self.log("🎉 All checks passed!")
        else:
            self.log("❌ Critical issues found:")
            for issue in summary['critical_issues']:
                self.log(f"  - {issue}")

        if summary['warnings']:
            self.log("⚠️ Warnings:")
            for warning in summary['warnings']:
                self.log(f"  - {warning}")

        return report

if __name__ == "__main__":
    diagnostics = IVALTDiagnostics()
    diagnostics.run_all_checks()
```

### Usage

```bash
# Run comprehensive diagnostics
python3 diagnostic_script.py

# Run specific checks
python3 diagnostic_script.py --check network
python3 diagnostic_script.py --check script
python3 diagnostic_script.py --check api
```

## Getting Help

### Self-Service Resources

1. **Documentation**: Check README.md and docs/ folder
2. **Diagnostic Scripts**: Use provided diagnostic tools
3. **Log Analysis**: Review OpenVPN and script logs
4. **Community**: GitHub Issues and Discussions

### Professional Support

- **Email**: support@ivalt.com
- **Priority**: Critical issues get fastest response
- **Response Time**: 24-48 hours for non-critical issues
- **Escalation**: Available for enterprise customers

### Support Information to Include

When requesting support, please include:

1. **Diagnostic Report**: Run diagnostic script and attach report
2. **Error Messages**: Complete error messages and logs
3. **Configuration**: Relevant configuration details (sanitized)
4. **Environment**: System and network information
5. **Steps to Reproduce**: Detailed reproduction steps

---

_For additional troubleshooting resources, please refer to the [Installation Guide](INSTALLATION.md) or [API Reference](API_REFERENCE.md)._
