# Installation Guide

This guide provides detailed instructions for installing and configuring the OpenVPN iVALT 2FA Integration.

## Table of Contents

- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Components

1. **OpenVPN Access Server**

   - Version 2.8 or higher
   - Administrative access
   - Post-authentication script support

2. **iVALT Account**

   - Valid iVALT API credentials
   - User accounts configured in iVALT system
   - Mobile app installed on user devices

3. **Python Environment**
   - Python 3.7 or higher
   - pip package manager
   - Network connectivity to iVALT APIs

### Optional Components

- **Development Tools** (for customization)
  - Git
  - Virtual environment tools
  - Code editor with Python support

## System Requirements

### Minimum Requirements

- **CPU**: 1 core, 2.0 GHz
- **RAM**: 512 MB
- **Storage**: 100 MB free space
- **Network**: Stable internet connection
- **OS**: Linux, Windows, or macOS

### Recommended Requirements

- **CPU**: 2 cores, 2.4 GHz
- **RAM**: 1 GB
- **Storage**: 500 MB free space
- **Network**: High-speed internet connection
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)

### Network Requirements

- **Outbound HTTPS**: Port 443 to `api.ivalt.com`
- **DNS Resolution**: Access to resolve `api.ivalt.com`
- **Firewall**: Allow outbound connections to iVALT APIs

## Installation Methods

### Method 1: Direct Installation

#### Step 1: Download the Script

```bash
# Download the main script
wget https://raw.githubusercontent.com/iVALT-Inc/openvpn-ivalt-2fa/main/main.py

# Or clone the repository
git clone https://github.com/iVALT-Inc/openvpn-ivalt-2fa.git
cd openvpn-ivalt-2fa
```

#### Step 2: Install Dependencies

```bash
# Install Python dependencies
pip install requests>=2.28.0

# Or install from requirements.txt
pip install -r requirements.txt
```

#### Step 3: Configure the Script

```bash
# Edit the script to add your iVALT API key
nano main.py

# Find and replace the placeholder
IVALT_SECRET_KEY = "your_actual_api_key_here"
```

#### Step 4: Set Permissions

```bash
# Make the script executable
chmod +x main.py

# Ensure proper ownership
chown openvpn:openvpn main.py
```

### Method 2: Package Installation

#### Step 1: Install from PyPI

```bash
# Install the package
pip install post-auth-2fa-ivalt

# Or install with development dependencies
pip install post-auth-2fa-ivalt[dev]
```

#### Step 2: Locate the Script

```bash
# Find the installed script
python -c "import main; print(main.__file__)"

# Or use the package script
which post-auth-2fa-ivalt
```

#### Step 3: Configure the Script

```bash
# Edit the configuration
nano /path/to/installed/main.py

# Update the API key
IVALT_SECRET_KEY = "your_actual_api_key_here"
```

### Method 3: Docker Installation

#### Step 1: Create Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY main.py .

CMD ["python", "main.py"]
```

#### Step 2: Build and Run

```bash
# Build the image
docker build -t openvpn-ivalt-2fa .

# Run the container
docker run -d --name ivalt-2fa openvpn-ivalt-2fa
```

## Configuration

### OpenVPN Access Server Configuration

#### Step 1: Access Admin Interface

1. Open your web browser
2. Navigate to `https://your-openvpn-server:943/admin`
3. Log in with administrator credentials

#### Step 2: Configure Post-Authentication Script

1. Go to **Configuration** → **Authentication**
2. Scroll down to **Post-Authentication Script**
3. Enter the full path to your `main.py` script
4. Click **Save Settings**

#### Step 3: Restart Services

1. Go to **Status** → **System Status**
2. Click **Restart Services**
3. Wait for services to restart

### Script Configuration

#### API Key Configuration

```python
# In main.py, update the API key
IVALT_SECRET_KEY = "your_ivalt_secret_key_here"
```

#### Timeout Configuration

```python
# Adjust timeout values if needed
while (time.time() - start_time) < 60:  # 60 seconds timeout
    time.sleep(5)  # 5 seconds between retries
```

#### Error Handling Configuration

```python
# Customize error messages
if error_msg in ['INVALID_TIMEZONE', 'INVALID_GEOFENCE']:
    msg = error_msg
    print(f"{msg} - Exiting due to error")
    break
```

### Environment Variables

#### Option 1: Direct Configuration

```python
# In main.py
IVALT_SECRET_KEY = "your_api_key_here"
```

#### Option 2: Environment Variable

```bash
# Set environment variable
export IVALT_SECRET_KEY="your_api_key_here"

# Or in .env file
echo "IVALT_SECRET_KEY=your_api_key_here" >> .env
```

#### Option 3: Configuration File

```python
# Create config.py
import os
from dotenv import load_dotenv

load_dotenv()

IVALT_SECRET_KEY = os.getenv('IVALT_SECRET_KEY', 'default_key')
```

## Verification

### Test Script Execution

#### Step 1: Manual Test

```bash
# Test the script directly
python main.py

# Check for errors
echo $?
```

#### Step 2: API Connectivity Test

```python
# Create test script
cat > test_api.py << 'EOF'
import requests

def test_ivalt_api():
    url = "https://api.ivalt.com/get-user-by-email"
    headers = {
        "x-api-key": "your_api_key_here",
        "Content-Type": "application/json"
    }
    payload = {"email": "test@example.com"}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_ivalt_api()
EOF

# Run the test
python test_api.py
```

#### Step 3: OpenVPN Integration Test

1. **Create Test User**

   - Add a test user to OpenVPN Access Server
   - Ensure the user exists in iVALT system

2. **Test Authentication**

   - Attempt VPN connection with test user
   - Verify 2FA prompt appears
   - Complete authentication process

3. **Verify Logs**
   - Check OpenVPN Access Server logs
   - Verify script execution
   - Confirm successful authentication

### Log Verification

#### OpenVPN Access Server Logs

```bash
# Check authentication logs
tail -f /var/log/openvpnas.log

# Check script execution logs
grep "post_auth" /var/log/openvpnas.log
```

#### Script Logs

```bash
# Add logging to script
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ivalt-2fa.log'),
        logging.StreamHandler()
    ]
)
```

## Troubleshooting

### Common Installation Issues

#### Issue 1: Permission Denied

**Symptoms**: Script fails to execute with permission errors

**Solution**:

```bash
# Fix permissions
chmod +x main.py
chown openvpn:openvpn main.py

# Verify permissions
ls -la main.py
```

#### Issue 2: Python Not Found

**Symptoms**: "python: command not found" error

**Solution**:

```bash
# Install Python
sudo apt update
sudo apt install python3 python3-pip

# Or use python3 explicitly
python3 main.py
```

#### Issue 3: Dependencies Missing

**Symptoms**: ImportError for requests module

**Solution**:

```bash
# Install dependencies
pip install requests

# Or use pip3
pip3 install requests

# Verify installation
python -c "import requests; print('OK')"
```

### Configuration Issues

#### Issue 1: API Key Invalid

**Symptoms**: 401 Unauthorized errors from iVALT API

**Solution**:

1. Verify API key is correct
2. Check API key permissions
3. Contact iVALT support for key validation

#### Issue 2: Network Connectivity

**Symptoms**: Connection timeout or network errors

**Solution**:

```bash
# Test connectivity
ping api.ivalt.com

# Test HTTPS connectivity
curl -I https://api.ivalt.com

# Check firewall rules
sudo ufw status
```

#### Issue 3: OpenVPN Integration

**Symptoms**: Script not executing during authentication

**Solution**:

1. Verify script path in OpenVPN configuration
2. Check script permissions
3. Restart OpenVPN services
4. Review OpenVPN logs

### Performance Issues

#### Issue 1: Slow Authentication

**Symptoms**: Long delays during authentication

**Solution**:

```python
# Reduce timeout values
while (time.time() - start_time) < 30:  # Reduce from 60 to 30 seconds
    time.sleep(2)  # Reduce from 5 to 2 seconds
```

#### Issue 2: High Resource Usage

**Symptoms**: High CPU or memory usage

**Solution**:

1. Monitor resource usage
2. Optimize retry logic
3. Consider load balancing
4. Review API call frequency

### Security Issues

#### Issue 1: API Key Exposure

**Symptoms**: API key visible in logs or configuration

**Solution**:

1. Use environment variables
2. Implement secure key storage
3. Rotate API keys regularly
4. Review access logs

#### Issue 2: Network Security

**Symptoms**: Unencrypted communication or security warnings

**Solution**:

1. Use HTTPS only
2. Implement certificate validation
3. Review firewall rules
4. Monitor network traffic

## Advanced Configuration

### Custom Error Handling

```python
# Custom error messages
ERROR_MESSAGES = {
    'INVALID_TIMEZONE': 'Access denied: Invalid timezone',
    'INVALID_GEOFENCE': 'Access denied: Location not allowed',
    'AUTHENTICATION_FAILED': 'Access denied: Authentication failed'
}

def handle_error(error_code):
    return ERROR_MESSAGES.get(error_code, 'Access denied: Unknown error')
```

### Logging Configuration

```python
# Advanced logging setup
import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    logger = logging.getLogger('ivalt_2fa')
    logger.setLevel(logging.DEBUG)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        '/var/log/ivalt-2fa.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )

    # Console handler
    console_handler = logging.StreamHandler()

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
```

### Monitoring Integration

```python
# Health check endpoint
def health_check():
    try:
        # Test API connectivity
        response = requests.get('https://api.ivalt.com/health', timeout=5)
        return response.status_code == 200
    except:
        return False

# Metrics collection
def collect_metrics():
    metrics = {
        'total_requests': 0,
        'successful_auths': 0,
        'failed_auths': 0,
        'average_response_time': 0
    }
    return metrics
```

## Support

### Getting Help

- **Documentation**: Check this guide and README.md
- **Issues**: Report issues on GitHub
- **Community**: Join discussions on GitHub
- **Professional Support**: Contact support@ivalt.com

### Useful Resources

- [OpenVPN Access Server Documentation](https://openvpn.net/static-links/post-auth-custom-authentication)
- [iVALT API Documentation](https://docs.ivalt.com)
- [Python Requests Documentation](https://docs.python-requests.org)
- [OpenVPN Community Forum](https://forums.openvpn.net)

---

_For additional help, please refer to the [Troubleshooting Guide](TROUBLESHOOTING.md) or contact support._
