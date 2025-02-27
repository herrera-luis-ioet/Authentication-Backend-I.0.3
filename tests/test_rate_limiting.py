import pytest
import json
from flask import current_app

def test_login_rate_limit(app, client):
    """Test rate limiting on login endpoint."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Make multiple requests to trigger rate limit
    for i in range(11):  # Limit is 10 per minute
        response = client.post('/auth/login',
            json={'username': 'testuser', 'password': 'Test@123456'}
        )
        
        if i < 10:
            assert response.status_code != 429
        else:
            assert response.status_code == 429
            data = json.loads(response.data)
            assert 'error' in data
            assert 'Rate limit exceeded' in data['error']
            assert 'retry_after' in data

def test_register_rate_limit(app, client):
    """Test rate limiting on register endpoint."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Make multiple requests to trigger rate limit
    for i in range(6):  # Limit is 5 per minute
        response = client.post('/auth/register',
            json={'username': f'newuser{i}', 'password': 'Test@123456'}
        )
        
        if i < 5:
            assert response.status_code != 429
        else:
            assert response.status_code == 429
            data = json.loads(response.data)
            assert 'error' in data
            assert 'Rate limit exceeded' in data['error']

def test_refresh_token_rate_limit(app, client, auth_headers):
    """Test rate limiting on token refresh endpoint."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Make multiple requests to trigger rate limit
    for i in range(11):  # Limit is 10 per minute
        response = client.post('/auth/refresh',
            headers=auth_headers
        )
        
        if i < 10:
            assert response.status_code != 429
        else:
            assert response.status_code == 429
            data = json.loads(response.data)
            assert 'error' in data
            assert 'Rate limit exceeded' in data['error']

def test_rate_limit_headers(app, client):
    """Test rate limit headers in response."""
    app.config['RATELIMIT_ENABLED'] = True
    
    response = client.post('/auth/login',
        json={'username': 'testuser', 'password': 'Test@123456'}
    )
    
    # Check for rate limit headers
    assert 'X-RateLimit-Limit' in response.headers
    assert 'X-RateLimit-Remaining' in response.headers
    assert 'X-RateLimit-Reset' in response.headers

def test_rate_limit_reset(app, client):
    """Test rate limit reset functionality."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Make requests until rate limit is hit
    for _ in range(11):
        client.post('/auth/login',
            json={'username': 'testuser', 'password': 'Test@123456'}
        )
    
    response = client.post('/auth/login',
        json={'username': 'testuser', 'password': 'Test@123456'}
    )
    assert response.status_code == 429
    
    # Get reset time from headers
    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
    assert reset_time > 0

def test_rate_limit_bypass_attempts(app, client):
    """Test attempts to bypass rate limiting."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Make requests with different headers to try bypassing
    headers = [
        {},
        {'X-Forwarded-For': '1.2.3.4'},
        {'X-Real-IP': '1.2.3.4'},
        {'X-Forwarded-For': '1.2.3.4,5.6.7.8'},
    ]
    
    # Make enough requests to hit rate limit
    for _ in range(5):
        for header in headers:
            response = client.post('/auth/register',
                json={'username': 'test', 'password': 'Test@123456'},
                headers=header
            )
    
    # Verify rate limit is enforced regardless of headers
    for header in headers:
        response = client.post('/auth/register',
            json={'username': 'test', 'password': 'Test@123456'},
            headers=header
        )
        assert response.status_code == 429

def test_rate_limit_per_endpoint(app, client, auth_headers):
    """Test that rate limits are applied per endpoint."""
    app.config['RATELIMIT_ENABLED'] = True
    
    # Test login endpoint
    for i in range(11):
        response = client.post('/auth/login',
            json={'username': 'testuser', 'password': 'Test@123456'}
        )
    assert response.status_code == 429
    
    # Test that register endpoint still works
    response = client.post('/auth/register',
        json={'username': 'newuser', 'password': 'Test@123456'}
    )
    assert response.status_code != 429
    
    # Test that refresh endpoint still works
    response = client.post('/auth/refresh',
        headers=auth_headers
    )
    assert response.status_code != 429