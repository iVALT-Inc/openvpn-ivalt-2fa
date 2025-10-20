# Contributing to OpenVPN iVALT 2FA Integration

Thank you for your interest in contributing to the OpenVPN iVALT 2FA Integration project! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)
- [Issue Reporting](#issue-reporting)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct. By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Git
- Basic understanding of OpenVPN Access Server
- Familiarity with iVALT API (helpful but not required)

### Development Setup

1. **Fork the Repository**

   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/iVALT-Inc/openvpn-ivalt-2fa.git
   cd openvpn-ivalt-2fa
   ```

2. **Set Up Development Environment**

   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install dependencies
   pip install -e ".[dev]"
   ```

3. **Configure Pre-commit Hooks** (Optional but recommended)
   ```bash
   pre-commit install
   ```

## Contributing Process

### Types of Contributions

We welcome several types of contributions:

- 🐛 **Bug Fixes**: Fix issues and improve reliability
- ✨ **New Features**: Add new functionality
- 📚 **Documentation**: Improve docs and examples
- 🧪 **Tests**: Add or improve test coverage
- 🔧 **Refactoring**: Improve code quality and maintainability
- 🌐 **Translations**: Add language support

### Workflow

1. **Create an Issue** (for significant changes)

   - Describe the problem or feature request
   - Use appropriate labels
   - Wait for maintainer feedback

2. **Create a Branch**

   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

3. **Make Changes**

   - Follow code style guidelines
   - Add tests for new functionality
   - Update documentation as needed

4. **Test Your Changes**

   ```bash
   # Run all tests
   pytest

   # Run with coverage
   pytest --cov=main --cov-report=html

   # Check code style
   black main.py
   isort main.py
   flake8 main.py

   # Type checking
   mypy main.py
   ```

5. **Commit Changes**

   ```bash
   git add .
   git commit -m "feat: add new authentication method"
   ```

6. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style Guidelines

### Python Style

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- **Line Length**: 88 characters (Black default)
- **Import Order**: isort with black profile
- **Type Hints**: Required for all functions
- **Docstrings**: Google style for all public functions

### Formatting Tools

```bash
# Format code
black main.py

# Sort imports
isort main.py

# Lint code
flake8 main.py

# Type checking
mypy main.py
```

### Code Examples

**Good:**

```python
def ivalt_auth_request_sent(mobile: str) -> bool:
    """Send authentication request to user's mobile device.

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

**Bad:**

```python
def ivalt_auth_request_sent(mobile):
    url="https://api.ivalt.com/biometric-auth-request"
    headers={"x-api-key":IVALT_SECRET_KEY,"Content-Type":"application/json"}
    payload={"mobile":mobile}
    try:
        response=requests.post(url,json=payload,headers=headers,timeout=300)
        if response.status_code==200:
            return True
        else:
            return False
    except:
        return False
```

## Testing Guidelines

### Test Structure

```
tests/
├── unit/
│   ├── test_auth_functions.py
│   └── test_ivalt_integration.py
├── integration/
│   └── test_openvpn_integration.py
└── fixtures/
    └── sample_responses.json
```

### Writing Tests

**Unit Tests:**

```python
import pytest
from unittest.mock import patch, Mock
from main import ivalt_auth_request_sent

def test_ivalt_auth_request_sent_success():
    """Test successful authentication request."""
    with patch('main.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = ivalt_auth_request_sent("+1234567890")

        assert result is True
        mock_post.assert_called_once()

def test_ivalt_auth_request_sent_failure():
    """Test failed authentication request."""
    with patch('main.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = ivalt_auth_request_sent("+1234567890")

        assert result is False
```

**Integration Tests:**

```python
@pytest.mark.integration
def test_full_authentication_flow():
    """Test complete authentication flow with real API calls."""
    # This would test against a test iVALT environment
    pass
```

### Test Markers

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests

## Documentation Guidelines

### README Updates

When adding new features:

- Update the Features section
- Add installation/configuration steps
- Include usage examples
- Update troubleshooting section

### Code Documentation

- **Docstrings**: Required for all public functions
- **Comments**: Explain complex logic
- **Type Hints**: Required for all function parameters and return values

### API Documentation

Document all iVALT API interactions:

- Endpoint URLs
- Request/response formats
- Error conditions
- Authentication requirements

## Issue Reporting

### Bug Reports

Use the bug report template and include:

1. **Environment Information**

   - OpenVPN Access Server version
   - Python version
   - Operating system

2. **Steps to Reproduce**

   - Clear, numbered steps
   - Expected vs actual behavior

3. **Error Messages**

   - Full error logs
   - Screenshots if applicable

4. **Additional Context**
   - Configuration details
   - Network setup
   - iVALT account information (sanitized)

### Feature Requests

Use the feature request template and include:

1. **Problem Description**

   - What problem does this solve?
   - Current workarounds

2. **Proposed Solution**

   - Detailed description
   - Alternative solutions considered

3. **Additional Context**
   - Use cases
   - Priority level

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] Type hints added
- [ ] No breaking changes (or clearly documented)

### PR Description Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings or errors
```

### Review Process

1. **Automated Checks**

   - CI/CD pipeline runs tests
   - Code style validation
   - Security scanning

2. **Maintainer Review**

   - Code quality review
   - Architecture review
   - Security review

3. **Testing**
   - Manual testing by maintainers
   - Integration testing
   - Performance testing

### After Approval

- Maintainers will merge the PR
- Changes will be included in the next release
- Contributors will be credited in the changelog

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Schedule

- **Patch releases**: As needed for critical fixes
- **Minor releases**: Monthly for new features
- **Major releases**: Quarterly for significant changes

## Community

### Getting Help

- 📧 **Email**: support@ivalt.com
- 💬 **Discussions**: GitHub Discussions
- 🐛 **Issues**: GitHub Issues
- 📖 **Wiki**: Project Wiki

### Recognition

Contributors will be:

- Listed in the README
- Mentioned in release notes
- Credited in the changelog

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to OpenVPN iVALT 2FA Integration! 🚀
