import pytest
import json
from app.auth.models import User

def test_register_valid_user(client):
    """Test user registration with valid data."""
    response = client.post('/auth/register',
        json={
            'username': 'newuser',
            'password': 'Test@123456'
        }
    )
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'message' in data
    assert 'user' in data
    assert data['user']['username'] == 'newuser'

def test_register_invalid_data(client, invalid_user_data):
    """Test user registration with invalid data."""
    test_cases = [
        (invalid_user_data['missing_fields'], 'Username and password are required'),
        (invalid_user_data['invalid_username'], 'Invalid username format'),
        (invalid_user_data['weak_password'], 'Password must be'),
        (invalid_user_data['long_username'], 'Invalid username format'),
        (invalid_user_data['special_chars'], 'Invalid username format')
    ]
    
    for data, expected_error in test_cases:
        response = client.post('/auth/register', json=data)
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'error' in response_data
        assert expected_error in response_data['error']

def test_register_duplicate_username(client, test_user):
    """Test registration with existing username."""
    response = client.post('/auth/register',
        json={
            'username': test_user.username,
            'password': 'Test@123456'
        }
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Username already exists' in data['error']

def test_login_valid_credentials(client, test_user):
    """Test login with valid credentials."""
    response = client.post('/auth/login',
        json={
            'username': test_user.username,
            'password': 'Test@123456'
        }
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data

def test_login_invalid_credentials(client):
    """Test login with invalid credentials."""
    test_cases = [
        ({'username': 'nonexistent', 'password': 'Test@123456'}, 'Invalid username or password'),
        ({'username': 'testuser', 'password': 'wrongpass'}, 'Invalid username or password'),
        ({}, 'Username and password are required'),
        ({'username': 'testuser'}, 'Username and password are required'),
        ({'password': 'Test@123456'}, 'Username and password are required')
    ]
    
    for data, expected_error in test_cases:
        response = client.post('/auth/login', json=data)
        assert response.status_code in [400, 401]
        response_data = json.loads(response.data)
        assert 'error' in response_data
        assert expected_error in response_data['error']

def test_refresh_token_valid(client, auth_headers):
    """Test token refresh with valid refresh token."""
    response = client.post('/auth/refresh',
        headers={'Authorization': auth_headers['refresh']}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data

def test_refresh_token_invalid(client):
    """Test token refresh with invalid tokens."""
    test_cases = [
        ('', 'Refresh token is required'),
        ('Bearer invalid.token.format', 'Invalid refresh token'),
        ('Bearer ', 'Refresh token is required'),
        ('not_bearer_format', 'Refresh token is required')
    ]
    
    for token, expected_error in test_cases:
        response = client.post('/auth/refresh',
            headers={'Authorization': token}
        )
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert expected_error in data['error']

def test_protected_route_access(client, auth_headers):
    """Test access to protected route."""
    # Test with valid token
    response = client.get('/auth/protected',
        headers=auth_headers['access']
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'user' in data
    
    # Test without token
    response = client.get('/auth/protected')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Token is missing' in data['error']
    
    # Test with invalid token format
    response = client.get('/auth/protected',
        headers={'Authorization': 'Bearer invalid.token.format'}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid token' in data['error']

def test_login_session_flow(client):
    """Test complete login session flow."""
    # Register new user
    register_response = client.post('/auth/register',
        json={
            'username': 'flowuser',
            'password': 'Test@123456'
        }
    )
    assert register_response.status_code == 201
    
    # Login
    login_response = client.post('/auth/login',
        json={
            'username': 'flowuser',
            'password': 'Test@123456'
        }
    )
    assert login_response.status_code == 200
    tokens = json.loads(login_response.data)
    
    # Access protected route
    protected_response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {tokens["access_token"]}'}
    )
    assert protected_response.status_code == 200
    
    # Refresh tokens
    refresh_response = client.post('/auth/refresh',
        headers={'Authorization': f'Bearer {tokens["refresh_token"]}'}
    )
    assert refresh_response.status_code == 200
    new_tokens = json.loads(refresh_response.data)
    
    # Verify new tokens work
    new_protected_response = client.get('/auth/protected',
        headers={'Authorization': f'Bearer {new_tokens["access_token"]}'}
    )
    assert new_protected_response.status_code == 200

def test_error_responses(client):
    """Test error response format and status codes."""
    test_cases = [
        # Registration errors
        ('/auth/register', 'POST', {}, 400),
        ('/auth/register', 'POST', {'username': 'a'*100}, 400),
        
        # Login errors
        ('/auth/login', 'POST', {}, 400),
        ('/auth/login', 'POST', {'username': 'nonexistent'}, 400),
        
        # Protected route errors
        ('/auth/protected', 'GET', None, 401),
        
        # Refresh token errors
        ('/auth/refresh', 'POST', None, 401)
    ]
    
    for endpoint, method, data, expected_status in test_cases:
        if method == 'POST':
            response = client.post(endpoint, json=data)
        else:
            response = client.get(endpoint)
            
        assert response.status_code == expected_status
        response_data = json.loads(response.data)
        assert 'error' in response_data
        assert isinstance(response_data['error'], str)

def test_concurrent_login_sessions(client, test_user):
    """Test handling of concurrent login sessions."""
    # First login
    response1 = client.post('/auth/login',
        json={
            'username': test_user.username,
            'password': 'Test@123456'
        }
    )
    tokens1 = json.loads(response1.data)
    
    # Second login
    response2 = client.post('/auth/login',
        json={
            'username': test_user.username,
            'password': 'Test@123456'
        }
    )
    tokens2 = json.loads(response2.data)
    
    # Both sessions should work
    for tokens in [tokens1, tokens2]:
        response = client.get('/auth/protected',
            headers={'Authorization': f'Bearer {tokens["access_token"]}'}
        )
        assert response.status_code == 200
        
    # Both refresh tokens should work
    for tokens in [tokens1, tokens2]:
        response = client.post('/auth/refresh',
            headers={'Authorization': f'Bearer {tokens["refresh_token"]}'}
        )
        assert response.status_code == 200