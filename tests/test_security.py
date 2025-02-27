import pytest
import json
from datetime import datetime, timedelta
import jwt

def test_security_headers(client):
    """Test security headers in response."""
    response = client.get('/auth/protected')
    
    # Check security headers
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert 'max-age=31536000' in response.headers.get('Strict-Transport-Security', '')

def test_password_validation(client):
    """Test password validation rules."""
    test_cases = [
        ('short', 'Password must be at least 8 characters'),
        ('nouppercasepass1!', 'Password must contain uppercase'),
        ('NOLOWERCASEPASS1!', 'Password must contain lowercase'),
        ('NoSpecialChars123', 'Password must contain special characters'),
        ('NoNumbers!@#$%^&', 'Password must contain numbers')
    ]
    
    for password, expected_error in test_cases:
        response = client.post('/auth/register',
            json={'username': 'testuser', 'password': password}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Password must be' in data['error']

def test_token_expiration(app, client, test_user, expired_token):
    """Test token expiration handling."""
    # Test expired token
    response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {expired_token}'}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Token has expired' in data['error']
    
    # Test refresh token expiration
    response = client.post('/auth/refresh',
        headers={'Authorization': f'Bearer {expired_token}'}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Refresh token has expired' in data['error']

def test_token_tampering(app, client, auth_headers):
    """Test handling of tampered tokens."""
    # Test invalid signature
    tampered_token = auth_headers['Authorization'].split()[1] + 'tampered'
    response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {tampered_token}'}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Invalid token' in data['error']
    
    # Test modified payload
    invalid_token = jwt.encode(
        {'user_id': 999999, 'exp': datetime.utcnow() + timedelta(minutes=15)},
        'wrong_secret',
        algorithm='HS256'
    )
    response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {invalid_token}'}
    )
    assert response.status_code == 401

def test_brute_force_protection(app, client):
    """Test protection against brute force attacks."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Attempt multiple failed logins
    for _ in range(11):
        response = client.post('/auth/login',
            json={'username': 'testuser', 'password': 'wrong_password'}
        )
    
    assert response.status_code == 429
    data = json.loads(response.data)
    assert 'Rate limit exceeded' in data['error']

def test_concurrent_sessions(app, client, test_user):
    """Test handling of concurrent sessions."""
    # Get first set of tokens
    response1 = client.post('/auth/login',
        json={'username': test_user.username, 'password': 'Test@123456'}
    )
    tokens1 = json.loads(response1.data)
    
    # Get second set of tokens
    response2 = client.post('/auth/login',
        json={'username': test_user.username, 'password': 'Test@123456'}
    )
    tokens2 = json.loads(response2.data)
    
    # Verify both tokens are different
    assert tokens1['access_token'] != tokens2['access_token']
    assert tokens1['refresh_token'] != tokens2['refresh_token']
    
    # Verify both tokens work
    for tokens in [tokens1, tokens2]:
        response = client.get('/auth/protected',
            headers={'Authorization': f'Bearer {tokens["access_token"]}'}
        )
        assert response.status_code == 200

def test_token_reuse(app, client, test_user):
    """Test prevention of token reuse after refresh."""
    # Login to get tokens
    response = client.post('/auth/login',
        json={'username': test_user.username, 'password': 'Test@123456'}
    )
    tokens = json.loads(response.data)
    
    # Refresh tokens
    response = client.post('/auth/refresh',
        headers={'Authorization': f'Bearer {tokens["refresh_token"]}'}
    )
    new_tokens = json.loads(response.data)
    
    # Try to use old access token
    response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {tokens["access_token"]}'}
    )
    assert response.status_code == 401
    
    # Verify new tokens work
    response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {new_tokens["access_token"]}'}
    )
    assert response.status_code == 200

def test_csrf_protection(client):
    """Test CSRF protection measures."""
    # Test without CSRF token
    response = client.post('/auth/login',
        json={'username': 'testuser', 'password': 'Test@123456'},
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert response.status_code == 200
    
    # Test with modified origin
    response = client.post('/auth/login',
        json={'username': 'testuser', 'password': 'Test@123456'},
        headers={
            'Origin': 'http://malicious-site.com',
            'X-Requested-With': 'XMLHttpRequest'
        }
    )
    assert response.status_code in [400, 403]  # Either is acceptable

def test_secure_headers_policy(client):
    """Test secure headers policy."""
    response = client.get('/auth/protected')
    headers = response.headers
    
    # Content Security Policy
    assert 'X-Content-Type-Options' in headers
    assert headers['X-Content-Type-Options'] == 'nosniff'
    
    # Frame options
    assert 'X-Frame-Options' in headers
    assert headers['X-Frame-Options'] == 'DENY'
    
    # XSS Protection
    assert 'X-XSS-Protection' in headers
    assert headers['X-XSS-Protection'] == '1; mode=block'
    
    # HSTS
    assert 'Strict-Transport-Security' in headers
    hsts = headers['Strict-Transport-Security']
    assert 'max-age=31536000' in hsts
    assert 'includeSubDomains' in hsts