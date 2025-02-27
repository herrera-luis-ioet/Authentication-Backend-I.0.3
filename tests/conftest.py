import pytest
from app import create_app
from app.auth.models import db, User
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

@pytest.fixture
def app():
    """Create and configure a test Flask application."""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture
def test_user(app):
    """Create a test user."""
    user = User(username='testuser', password='Test@123')
    with app.app_context():
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def auth_headers(app, test_user):
    """Create authentication headers with valid tokens."""
    tokens = test_user.generate_tokens()
    return {
        'access': {'Authorization': f'Bearer {tokens["access_token"]}'},
        'refresh': {'Authorization': f'Bearer {tokens["refresh_token"]}'}
    }

@pytest.fixture
def expired_token(app, test_user):
    """Create an expired token for testing."""
    with app.app_context():
        return jwt.encode(
            {
                'user_id': test_user.id,
                'exp': datetime.utcnow() - timedelta(minutes=1)
            },
            app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )

@pytest.fixture
def invalid_token():
    """Create an invalid token for testing."""
    return 'invalid.token.format'

@pytest.fixture
def test_users(app):
    """Create multiple test users for rate limiting tests."""
    users = []
    for i in range(5):
        user = User(username=f'testuser{i}', password='Test@123')
        users.append(user)
    
    with app.app_context():
        for user in users:
            db.session.add(user)
        db.session.commit()
        return users

@pytest.fixture
def invalid_user_data():
    """Create invalid user data for testing."""
    return {
        'missing_fields': {},
        'invalid_username': {'username': 'u$', 'password': 'Test@123'},
        'weak_password': {'username': 'validuser', 'password': 'weak'},
        'long_username': {'username': 'a' * 81, 'password': 'Test@123'},
        'special_chars': {'username': 'test@user', 'password': 'Test@123'}
    }

@pytest.fixture
def corrupted_user(app):
    """Create a user with corrupted password hash for testing error cases."""
    user = User(username='corrupted', password='Test@123')
    user.password_hash = 'corrupted_hash'
    
    with app.app_context():
        db.session.add(user)
        db.session.commit()
        return user
import pytest
from flask import Flask
from app import create_app
from app.auth.models import db, User
import jwt
from datetime import datetime, timedelta

@pytest.fixture
def app():
    """Create and configure a test Flask application."""
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    app.config['RATELIMIT_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture
def test_user(app):
    """Create a test user."""
    user = User(
        username='testuser',
        password='Test@123456'
    )
    with app.app_context():
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def auth_headers(app, test_user):
    """Generate authentication headers with valid tokens."""
    access_token = jwt.encode(
        {
            'user_id': test_user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15)
        },
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    return {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

@pytest.fixture
def expired_token(app, test_user):
    """Generate an expired token for testing."""
    return jwt.encode(
        {
            'user_id': test_user.id,
            'exp': datetime.utcnow() - timedelta(minutes=15)
        },
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
