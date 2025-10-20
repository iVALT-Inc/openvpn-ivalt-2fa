# API Reference

This document provides detailed information about the iVALT API endpoints used by the OpenVPN iVALT 2FA Integration.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Endpoints](#endpoints)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)

## Overview

The iVALT API provides biometric authentication services for secure access control. The OpenVPN integration uses three main endpoints to implement 2FA functionality.

### Base URL

```
https://api.ivalt.com
```

### API Version

Current API version: `v1`

### Content Type

All requests and responses use `application/json` content type.

## Authentication

### API Key Authentication

All requests require an API key in the request headers:

```http
x-api-key: your_ivalt_secret_key_here
```

### Security Considerations

- Keep API keys secure and never expose them in logs
- Rotate API keys regularly
- Use environment variables for key storage
- Monitor API key usage

## Endpoints

### 1. Get User by Email

Retrieves user information including mobile number for authentication.

#### Request

```http
POST /get-user-by-email
Content-Type: application/json
x-api-key: your_api_key_here

{
  "email": "user@example.com"
}
```

#### Parameters

| Parameter | Type   | Required | Description          |
| --------- | ------ | -------- | -------------------- |
| email     | string | Yes      | User's email address |

#### Response

**Success (200 OK)**

```json
{
  "status": "success",
  "data": {
    "details": {
      "mobile_with_country_code": "+1234567890",
      "user_id": "user_123",
      "email": "user@example.com",
      "status": "active"
    }
  }
}
```

**Error (400 Bad Request)**

```json
{
  "status": "error",
  "error": {
    "code": "USER_NOT_FOUND",
    "detail": "User with email user@example.com not found"
  }
}
```

#### Implementation

```python
def ivalt_get_mobile_by_email(email: str) -> tuple[bool, Any]:
    """Get user's mobile number by email address.

    Args:
        email: User's email address

    Returns:
        Tuple of (success_status, mobile_number_or_error_message)
    """
    url = "https://api.ivalt.com/get-user-by-email"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {"email": email}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
    except requests.RequestException:
        return False, None

    if response.status_code != 200:
        error_data = response.json()
        return False, error_data['error']['detail']

    data = response.json()
    return True, data['data']['details']['mobile_with_country_code']
```

### 2. Send Biometric Authentication Request

Sends a biometric authentication request to the user's mobile device.

#### Request

```http
POST /biometric-auth-request
Content-Type: application/json
x-api-key: your_api_key_here

{
  "mobile": "+1234567890"
}
```

#### Parameters

| Parameter | Type   | Required | Description                            |
| --------- | ------ | -------- | -------------------------------------- |
| mobile    | string | Yes      | User's mobile number with country code |

#### Response

**Success (200 OK)**

```json
{
  "status": "success",
  "message": "Authentication request sent successfully",
  "request_id": "req_123456789"
}
```

**Error (400 Bad Request)**

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_MOBILE",
    "detail": "Invalid mobile number format"
  }
}
```

#### Implementation

```python
def ivalt_auth_request_sent(mobile: str) -> bool:
    """Send biometric authentication request to user's mobile device.

    Args:
        mobile: User's mobile number with country code

    Returns:
        True if request sent successfully, False otherwise
    """
    url = "https://api.ivalt.com/biometric-auth-request"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {"mobile": mobile}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        return response.status_code == 200
    except requests.RequestException:
        return False
```

### 3. Verify Biometric Authentication Result

Verifies the result of the biometric authentication request with geofencing validation.

#### Request

```http
POST /biometric-geo-fence-auth-results
Content-Type: application/json
x-api-key: your_api_key_here

{
  "mobile": "+1234567890"
}
```

#### Parameters

| Parameter | Type   | Required | Description                            |
| --------- | ------ | -------- | -------------------------------------- |
| mobile    | string | Yes      | User's mobile number with country code |

#### Response

**Success (200 OK)**

```json
{
  "status": "success",
  "message": "Authentication verified successfully",
  "result": {
    "authenticated": true,
    "timestamp": "2025-10-20T12:00:00Z",
    "location": {
      "latitude": 40.7128,
      "longitude": -74.006,
      "accuracy": 10
    }
  }
}
```

**Error - Invalid Timezone (400 Bad Request)**

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_TIMEZONE",
    "detail": "User's timezone does not match security requirements"
  }
}
```

**Error - Invalid Geofence (400 Bad Request)**

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_GEOFENCE",
    "detail": "User's location is outside allowed geofence boundaries"
  }
}
```

#### Implementation

```python
def ivalt_auth_request_verify(mobile: str) -> tuple[bool, str]:
    """Verify biometric authentication result with geofencing validation.

    Args:
        mobile: User's mobile number with country code

    Returns:
        Tuple of (success_status, error_message_if_failed)
    """
    url = "https://api.ivalt.com/biometric-geo-fence-auth-results"
    headers = {
        "x-api-key": IVALT_SECRET_KEY,
        "Content-Type": "application/json"
    }
    payload = {"mobile": mobile}

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
    except requests.RequestException:
        return False, None

    if response.status_code != 200:
        error_data = response.json()
        error_detail = error_data.get('error', {}).get('detail', '')

        if 'timezone' in error_detail:
            return False, 'INVALID_TIMEZONE'
        elif 'geofencing' in error_detail:
            return False, 'INVALID_GEOFENCE'

        return False, None

    return True, None
```

## Error Handling

### Common Error Codes

| Code                    | Description                    | Action                      |
| ----------------------- | ------------------------------ | --------------------------- |
| `USER_NOT_FOUND`        | User email not found in system | Verify user exists in iVALT |
| `INVALID_MOBILE`        | Mobile number format invalid   | Check mobile number format  |
| `INVALID_TIMEZONE`      | User's timezone not allowed    | Adjust timezone settings    |
| `INVALID_GEOFENCE`      | User's location not allowed    | Check geofencing rules      |
| `AUTHENTICATION_FAILED` | General authentication failure | Check user status           |
| `API_KEY_INVALID`       | API key is invalid or expired  | Verify API key              |
| `RATE_LIMIT_EXCEEDED`   | Too many requests              | Implement backoff           |

### Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "detail": "Human readable error message",
    "timestamp": "2025-10-20T12:00:00Z"
  }
}
```

### Error Handling Best Practices

1. **Always check HTTP status codes**
2. **Parse error responses for specific error codes**
3. **Implement retry logic for transient errors**
4. **Log errors for debugging**
5. **Provide user-friendly error messages**

## Rate Limiting

### Limits

- **Requests per minute**: 100
- **Requests per hour**: 1000
- **Burst limit**: 20 requests per second

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### Rate Limit Exceeded Response

```json
{
  "status": "error",
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "detail": "Rate limit exceeded. Try again later.",
    "retry_after": 60
  }
}
```

### Rate Limiting Implementation

```python
import time
from functools import wraps

def rate_limit_handler(func):
    """Decorator to handle rate limiting."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            if e.response and e.response.status_code == 429:
                retry_after = int(e.response.headers.get('Retry-After', 60))
                time.sleep(retry_after)
                return func(*args, **kwargs)
            raise
    return wrapper
```

## Examples

### Complete Authentication Flow

```python
import requests
import time
from typing import Tuple, Any

class IVALTClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.ivalt.com"

    def get_user_mobile(self, email: str) -> Tuple[bool, Any]:
        """Get user's mobile number by email."""
        url = f"{self.base_url}/get-user-by-email"
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {"email": email}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=300)
            if response.status_code == 200:
                data = response.json()
                mobile = data['data']['details']['mobile_with_country_code']
                return True, mobile
            else:
                error_data = response.json()
                return False, error_data['error']['detail']
        except requests.RequestException:
            return False, None

    def send_auth_request(self, mobile: str) -> bool:
        """Send biometric authentication request."""
        url = f"{self.base_url}/biometric-auth-request"
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {"mobile": mobile}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=300)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def verify_auth_result(self, mobile: str) -> Tuple[bool, str]:
        """Verify authentication result."""
        url = f"{self.base_url}/biometric-geo-fence-auth-results"
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {"mobile": mobile}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=300)
            if response.status_code == 200:
                return True, None
            else:
                error_data = response.json()
                error_detail = error_data.get('error', {}).get('detail', '')

                if 'timezone' in error_detail:
                    return False, 'INVALID_TIMEZONE'
                elif 'geofencing' in error_detail:
                    return False, 'INVALID_GEOFENCE'

                return False, None
        except requests.RequestException:
            return False, None

    def authenticate_user(self, email: str, timeout: int = 60) -> Tuple[bool, str]:
        """Complete authentication flow for a user."""
        # Get user's mobile number
        success, mobile = self.get_user_mobile(email)
        if not success:
            return False, mobile or "USER_NOT_FOUND"

        # Send authentication request
        if not self.send_auth_request(mobile):
            return False, "AUTHENTICATION_FAILED"

        # Wait for user response
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            success, error = self.verify_auth_result(mobile)
            if success:
                return True, None
            elif error in ['INVALID_TIMEZONE', 'INVALID_GEOFENCE']:
                return False, error

            time.sleep(5)  # Wait 5 seconds before retrying

        return False, "AUTHENTICATION_TIMEOUT"

# Usage example
client = IVALTClient("your_api_key_here")
success, error = client.authenticate_user("user@example.com")
if success:
    print("Authentication successful!")
else:
    print(f"Authentication failed: {error}")
```

### Error Handling Example

```python
def handle_api_error(response: requests.Response) -> str:
    """Handle API errors and return appropriate error message."""
    try:
        error_data = response.json()
        error_code = error_data.get('error', {}).get('code', 'UNKNOWN_ERROR')
        error_detail = error_data.get('error', {}).get('detail', 'Unknown error')

        error_messages = {
            'USER_NOT_FOUND': 'User not found in iVALT system',
            'INVALID_MOBILE': 'Invalid mobile number format',
            'INVALID_TIMEZONE': 'Access denied: Invalid timezone',
            'INVALID_GEOFENCE': 'Access denied: Location not allowed',
            'AUTHENTICATION_FAILED': 'Authentication failed',
            'API_KEY_INVALID': 'Invalid API key',
            'RATE_LIMIT_EXCEEDED': 'Rate limit exceeded'
        }

        return error_messages.get(error_code, error_detail)
    except ValueError:
        return f"HTTP {response.status_code}: {response.text}"
```

### Retry Logic Example

```python
import time
from functools import wraps

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry API calls on failure."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
            return None
        return wrapper
    return decorator

@retry_on_failure(max_retries=3, delay=1.0)
def make_api_request(url: str, headers: dict, payload: dict) -> requests.Response:
    """Make API request with retry logic."""
    return requests.post(url, json=payload, headers=headers, timeout=300)
```

## Testing

### Unit Testing

```python
import unittest
from unittest.mock import patch, Mock
from main import IVALTClient

class TestIVALTClient(unittest.TestCase):
    def setUp(self):
        self.client = IVALTClient("test_api_key")

    @patch('main.requests.post')
    def test_get_user_mobile_success(self, mock_post):
        """Test successful mobile number retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'details': {
                    'mobile_with_country_code': '+1234567890'
                }
            }
        }
        mock_post.return_value = mock_response

        success, mobile = self.client.get_user_mobile("test@example.com")

        self.assertTrue(success)
        self.assertEqual(mobile, '+1234567890')

    @patch('main.requests.post')
    def test_get_user_mobile_error(self, mock_post):
        """Test error handling for mobile number retrieval."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': {
                'detail': 'User not found'
            }
        }
        mock_post.return_value = mock_response

        success, error = self.client.get_user_mobile("test@example.com")

        self.assertFalse(success)
        self.assertEqual(error, 'User not found')

if __name__ == '__main__':
    unittest.main()
```

### Integration Testing

```python
import pytest
import requests

@pytest.mark.integration
def test_real_api_connection():
    """Test real API connection (requires valid API key)."""
    client = IVALTClient("real_api_key_here")

    # Test with a known test user
    success, result = client.get_user_mobile("test@example.com")

    if success:
        assert isinstance(result, str)
        assert result.startswith('+')
    else:
        assert isinstance(result, str)
        assert 'error' in result.lower()
```

## Security Considerations

### API Key Security

1. **Never log API keys**
2. **Use environment variables**
3. **Rotate keys regularly**
4. **Monitor key usage**

### Network Security

1. **Use HTTPS only**
2. **Validate SSL certificates**
3. **Implement request signing**
4. **Monitor for anomalies**

### Data Protection

1. **Minimize data collection**
2. **Encrypt sensitive data**
3. **Implement data retention policies**
4. **Regular security audits**

---

_For additional information, please refer to the [iVALT API Documentation](https://docs.ivalt.com) or contact support._
