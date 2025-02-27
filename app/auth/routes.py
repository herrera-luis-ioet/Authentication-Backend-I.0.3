from flask import Blueprint, request, jsonify, current_app, make_response
from werkzeug.exceptions import BadRequest, Unauthorized, TooManyRequests
from functools import update_wrapper
import jwt
from datetime import datetime
from functools import wraps
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .models import db, User

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def validate_password(password: str) -> bool:
    """Validate password complexity."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def validate_username(username: str) -> bool:
    """Validate username format."""
    if len(username) < 3 or len(username) > 32:
        return False
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False
    return True

auth_bp = Blueprint('auth', __name__)

@auth_bp.after_request
def add_security_headers(response):
    """Add security headers to response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@auth_bp.errorhandler(TooManyRequests)
def handle_rate_limit_error(e):
    """Handle rate limit exceeded error."""
    return jsonify({
        'error': 'Rate limit exceeded',
        'retry_after': e.description
    }), 429

def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            raise Unauthorized('Token is missing')
            
        try:
            data = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            current_user = User.get_by_id(data['user_id'])
            if not current_user:
                raise Unauthorized('Invalid token')
        except jwt.ExpiredSignatureError:
            raise Unauthorized('Token has expired')
        except jwt.InvalidTokenError:
            raise Unauthorized('Invalid token')
            
        return f(current_user, *args, **kwargs)
    return decorated

# PUBLIC_INTERFACE
@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user."""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            raise BadRequest('Username and password are required')
            
        username = data['username']
        password = data['password']
        
        if not validate_username(username):
            raise BadRequest('Invalid username format. Username must be 3-32 characters long and contain only letters, numbers, underscores, and hyphens.')
            
        if not validate_password(password):
            raise BadRequest('Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            
        if User.get_by_username(username):
            raise BadRequest('Username already exists')
            
        user = User(
            username=username,
            password=password
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': {'username': user.username}
        }), 201
        
    except BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

# PUBLIC_INTERFACE
@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Login user and return JWT tokens."""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            raise BadRequest('Username and password are required')
            
        user = User.get_by_username(data['username'])
        if not user or not user.check_password(data['password']):
            raise Unauthorized('Invalid username or password')
            
        tokens = user.generate_tokens()
        return jsonify(tokens), 200
        
    except (BadRequest, Unauthorized) as e:
        return jsonify({'error': str(e)}), e.code
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# PUBLIC_INTERFACE
@auth_bp.route('/refresh', methods=['POST'])
@limiter.limit("10 per minute")
def refresh_token():
    """Refresh access token using refresh token.
    
    Returns:
        JSON response with new access and refresh tokens
        
    Raises:
        Unauthorized: If refresh token is invalid or expired
        TooManyRequests: If rate limit is exceeded
    """
    try:
        refresh_token = request.headers.get('Authorization')
        if not refresh_token or not refresh_token.startswith('Bearer '):
            raise Unauthorized('Refresh token is required')
            
        token = refresh_token.split(' ')[1]
        try:
            data = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            user = User.get_by_id(data['user_id'])
            if not user:
                raise Unauthorized('Invalid token')
                
            tokens = user.generate_tokens()
            return jsonify(tokens), 200
            
        except jwt.ExpiredSignatureError:
            raise Unauthorized('Refresh token has expired')
        except jwt.InvalidTokenError:
            raise Unauthorized('Invalid refresh token')
            
    except Unauthorized as e:
        return jsonify({'error': str(e)}), e.code
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

# Example protected route
@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    """Example of a protected route."""
    return jsonify({
        'message': 'Access granted',
        'user': {'username': current_user.username}
    })
