import pytest
import os
from app import create_app
from app.auth.models import db, User
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import OperationalError

def get_database_url(request):
    """Helper function to get database URL based on test requirements."""
    # Default to SQLite for most tests
    database_url = os.getenv('TEST_DATABASE_URL', 'sqlite:///:memory:')
    
    # Allow tests to request MySQL specifically
    if request.node.get_closest_marker('mysql_required'):
        required_vars = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            pytest.skip(f"Missing required MySQL environment variables: {', '.join(missing_vars)}")
        
        database_url = 'mysql+pymysql://{}:{}@{}:{}/{}_test'.format(
            os.getenv('DB_USER'),
            os.getenv('DB_PASSWORD'),
            os.getenv('DB_HOST'),
            os.getenv('DB_PORT', '3306'),
            os.getenv('DB_NAME')
        )
        
        # Test MySQL connection before proceeding
        try:
            engine = create_engine(database_url)
            engine.connect()
            engine.dispose()
        except Exception as e:
            pytest.skip(f"Failed to connect to MySQL: {str(e)}")
            
    return database_url

@pytest.fixture
def app(request):
    """Create and configure a test Flask application."""
    database_url = get_database_url(request)
    
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    app.config['RATELIMIT_ENABLED'] = False
    
    # Configure MySQL connection pool for tests
    if 'mysql' in database_url:
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': 10,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'max_overflow': 5,
            'pool_pre_ping': True  # Enable connection health checks
        }
    
    with app.app_context():
        try:
            # Drop all tables first to ensure clean state
            db.drop_all()
            db.create_all()
            
            # For MySQL, ensure proper character set
            if 'mysql' in database_url:
                db.session.execute(text('SET NAMES utf8mb4'))
                db.session.execute(text('SET CHARACTER SET utf8mb4'))
                db.session.commit()
                
            yield app
            
        except Exception as e:
            pytest.skip(f"Database setup failed: {str(e)}")
            
        finally:
            db.session.remove()
            try:
                db.drop_all()
            except:
                pass  # Ignore cleanup errors

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
        'refresh': {'Authorization': f'Bearer {tokens["refresh_token"]}'},
        'Content-Type': 'application/json'
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

@pytest.fixture
def mysql_connection_params(request):
    """Get MySQL connection parameters for database migration tests."""
    if not request.node.get_closest_marker('mysql_required'):
        pytest.skip("This test requires MySQL")
        
    required_vars = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        pytest.skip(f"Missing required MySQL environment variables: {', '.join(missing_vars)}")
        
    return {
        'user': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD'),
        'host': os.getenv('DB_HOST'),
        'port': os.getenv('DB_PORT', '3306'),
        'database': f"{os.getenv('DB_NAME')}_test"
    }