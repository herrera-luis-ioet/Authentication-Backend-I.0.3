import pytest
from app.auth.models import User
from datetime import datetime
import jwt
from flask import current_app

def test_new_user(app):
    """Test creating a new user."""
    with app.app_context():
        user = User(username='newuser', password='Test@123')
        assert user.username == 'newuser'
        assert user.password_hash is not None
        assert user.password_hash != 'Test@123'
        assert isinstance(user.created_at, datetime)
        assert user.created_at <= datetime.utcnow()

def test_password_hashing(app):
    """Test password hashing and verification."""
    with app.app_context():
        user = User(username='testuser', password='Test@123')
        # Test password is hashed
        assert user.password_hash is not None
        assert user.password_hash != 'Test@123'
        assert len(user.password_hash) > 20  # Reasonable hash length
        
        # Test password verification
        assert user.check_password('Test@123') is True
        assert user.check_password('wrongpass') is False
        assert user.check_password('') is False
        assert user.check_password(None) is False

def test_token_generation(app):
    """Test token generation."""
    with app.app_context():
        user = User(username='tokenuser', password='Test@123')
        tokens = user.generate_tokens()
        
        # Test token structure
        assert 'access_token' in tokens
        assert 'refresh_token' in tokens
        assert isinstance(tokens['access_token'], str)
        assert isinstance(tokens['refresh_token'], str)
        
        # Verify access token contents
        access_data = jwt.decode(
            tokens['access_token'],
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        assert access_data['user_id'] == user.id
        assert 'exp' in access_data
        
        # Verify refresh token contents
        refresh_data = jwt.decode(
            tokens['refresh_token'],
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        assert refresh_data['user_id'] == user.id
        assert 'exp' in refresh_data
        
        # Verify different expiration times
        assert refresh_data['exp'] > access_data['exp']

def test_get_by_username(app, test_user):
    """Test retrieving user by username."""
    with app.app_context():
        # Test existing user
        found_user = User.get_by_username('testuser')
        assert found_user is not None
        assert found_user.username == 'testuser'
        assert found_user.id == test_user.id
        
        # Test non-existent user
        not_found_user = User.get_by_username('nonexistent')
        assert not_found_user is None
        
        # Test case sensitivity
        case_diff_user = User.get_by_username('TestUser')
        assert case_diff_user is None
        
        # Test special characters
        special_user = User.get_by_username('test@user')
        assert special_user is None

def test_get_by_id(app, test_user):
    """Test retrieving user by ID."""
    with app.app_context():
        # Test existing user
        found_user = User.get_by_id(test_user.id)
        assert found_user is not None
        assert found_user.username == 'testuser'
        assert found_user.id == test_user.id
        
        # Test non-existent user
        not_found_user = User.get_by_id(9999)
        assert not_found_user is None
        
        # Test invalid ID types
        assert User.get_by_id(None) is None
        assert User.get_by_id('invalid') is None
        assert User.get_by_id(-1) is None

def test_user_model_constraints(app):
    """Test User model constraints and edge cases."""
    with app.app_context():
        # Test username uniqueness
        user1 = User(username='uniqueuser', password='Test@123')
        db.session.add(user1)
        db.session.commit()
        
        user2 = User(username='uniqueuser', password='Test@123')
        with pytest.raises(Exception):  # Should raise integrity error
            db.session.add(user2)
            db.session.commit()
        db.session.rollback()
        
        # Test username length limits
        long_username = 'a' * 81  # Username limit is 80
        with pytest.raises(Exception):
            user = User(username=long_username, password='Test@123')
            db.session.add(user)
            db.session.commit()
        db.session.rollback()
        
        # Test null constraints
        with pytest.raises(Exception):
            user = User(username=None, password='Test@123')
            db.session.add(user)
            db.session.commit()
        db.session.rollback()
        
        with pytest.raises(Exception):
            user = User(username='nullpass', password=None)
            db.session.add(user)
            db.session.commit()
        db.session.rollback()
        
        # Test empty string constraints
        with pytest.raises(Exception):
            user = User(username='', password='Test@123')
            db.session.add(user)
            db.session.commit()
        db.session.rollback()
        
        with pytest.raises(Exception):
            user = User(username='emptypass', password='')
            db.session.add(user)
            db.session.commit()
        db.session.rollback()

def test_password_hash_security(app):
    """Test password hash security features."""
    with app.app_context():
        user = User(username='hashtest', password='Test@123')
        
        # Test hash randomization
        other_user = User(username='hashtest2', password='Test@123')
        assert user.password_hash != other_user.password_hash
        
        # Test hash length and format
        assert len(user.password_hash) >= 60  # bcrypt hash length
        assert user.password_hash.startswith('pbkdf2:sha256:')  # werkzeug format
        
        # Test password verification with various inputs
        assert not user.check_password('')
        assert not user.check_password(None)
        assert not user.check_password('Test@123 ')  # with space
        assert not user.check_password(' Test@123')  # with space
        assert not user.check_password('test@123')  # different case
        
        # Test hash immutability
        original_hash = user.password_hash
        user.check_password('WrongPassword')
        assert user.password_hash == original_hash

def test_token_security(app, test_user):
    """Test token generation security features."""
    with app.app_context():
        tokens1 = test_user.generate_tokens()
        tokens2 = test_user.generate_tokens()
        
        # Test token uniqueness
        assert tokens1['access_token'] != tokens2['access_token']
        assert tokens1['refresh_token'] != tokens2['refresh_token']
        
        # Test token format
        for token in [tokens1['access_token'], tokens1['refresh_token']]:
            # JWT format validation
            assert len(token.split('.')) == 3
            header, payload, signature = token.split('.')
            assert all(part for part in [header, payload, signature])
        
        # Test token expiration times
        access_data = jwt.decode(
            tokens1['access_token'],
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        refresh_data = jwt.decode(
            tokens1['refresh_token'],
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Access token should expire before refresh token
        assert access_data['exp'] < refresh_data['exp']
        # Access token should expire in ~15 minutes
        assert 14 * 60 <= refresh_data['exp'] - access_data['exp'] <= 16 * 60

def test_user_data_validation(app):
    """Test user data validation and sanitization."""
    with app.app_context():
        # Test username normalization
        user = User(username=' testuser ', password='Test@123')  # with spaces
        assert user.username == 'testuser'  # should be stripped
        
        # Test username character restrictions
        invalid_usernames = [
            'test@user',  # @ symbol
            'test/user',  # slash
            'test\\user',  # backslash
            'test user',  # space
            'test.user',  # dot
            'test#user',  # hash
            'test$user',  # dollar
        ]
        
        for invalid_username in invalid_usernames:
            with pytest.raises(Exception):
                user = User(username=invalid_username, password='Test@123')
                db.session.add(user)
                db.session.commit()
            db.session.rollback()

def test_error_handling(app, corrupted_user):
    """Test error handling in user operations."""
    with app.app_context():
        # Test corrupted password hash handling
        assert not corrupted_user.check_password('Test@123')
        
        # Test invalid token generation
        try:
            corrupted_user.generate_tokens()
            assert False, "Should raise an exception"
        except Exception:
            pass
        
        # Test invalid user queries
        assert User.get_by_id(None) is None
        assert User.get_by_id(-1) is None
        assert User.get_by_id(9999999) is None
        assert User.get_by_username(None) is None
        assert User.get_by_username('') is None
import pytest
from app.auth.models import User
from werkzeug.security import check_password_hash
import jwt
from datetime import datetime, timedelta

def test_create_user(app):
    """Test user creation with valid data."""
    username = "testuser1"
    password = "Test@123456"
    
    user = User(username=username, password=password)
    assert user.username == username
    assert user.password_hash != password
    assert check_password_hash(user.password_hash, password)

def test_password_hashing(app):
    """Test password hashing and verification."""
    user = User(username="testuser2", password="Test@123456")
    
    # Test that passwords are hashed
    assert user.password_hash != "Test@123456"
    
    # Test password verification
    assert user.check_password("Test@123456") is True
    assert user.check_password("wrongpassword") is False

def test_token_generation(app):
    """Test JWT token generation."""
    user = User(username="testuser3", password="Test@123456")
    with app.app_context():
        app.config['JWT_SECRET_KEY'] = 'test-key'
        tokens = user.generate_tokens()
        
        # Verify token structure
        assert 'access_token' in tokens
        assert 'refresh_token' in tokens
        
        # Decode and verify access token
        access_data = jwt.decode(
            tokens['access_token'],
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        assert access_data['user_id'] == user.id
        assert 'exp' in access_data
        
        # Decode and verify refresh token
        refresh_data = jwt.decode(
            tokens['refresh_token'],
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        assert refresh_data['user_id'] == user.id
        assert 'exp' in refresh_data

def test_get_by_username(app, test_user):
    """Test retrieving user by username."""
    with app.app_context():
        # Test existing user
        found_user = User.get_by_username(test_user.username)
        assert found_user is not None
        assert found_user.id == test_user.id
        
        # Test non-existent user
        not_found = User.get_by_username("nonexistent")
        assert not_found is None

def test_get_by_id(app, test_user):
    """Test retrieving user by ID."""
    with app.app_context():
        # Test existing user
        found_user = User.get_by_id(test_user.id)
        assert found_user is not None
        assert found_user.username == test_user.username
        
        # Test non-existent user
        not_found = User.get_by_id(9999)
        assert not_found is None

def test_token_expiration(app, test_user):
    """Test token expiration times."""
    with app.app_context():
        tokens = test_user.generate_tokens()
        
        # Verify access token expiration (15 minutes)
        access_data = jwt.decode(
            tokens['access_token'],
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        exp_time = datetime.fromtimestamp(access_data['exp'])
        assert (exp_time - datetime.utcnow()).total_seconds() <= 15 * 60
        
        # Verify refresh token expiration (30 days)
        refresh_data = jwt.decode(
            tokens['refresh_token'],
            app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        exp_time = datetime.fromtimestamp(refresh_data['exp'])
        assert (exp_time - datetime.utcnow()).total_seconds() <= 30 * 24 * 60 * 60
