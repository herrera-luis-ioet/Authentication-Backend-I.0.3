from flask import jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required
)
from app.auth import bp
from app.auth.models import User

@bp.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data['username']
    password = data['password']
    
    # Check if user already exists
    if User.get_by_username(username):
        return jsonify({'error': 'Username already exists'}), 400
    
    # Create new user
    user = User(username=username, password=password)
    # TODO: Save user to database
    
    return jsonify({'message': 'User created successfully'}), 201

@bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return tokens."""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.get_by_username(data['username'])
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    access_token = create_access_token(identity=user.username)
    refresh_token = create_refresh_token(identity=user.username)
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200

@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token."""
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    
    return jsonify({'access_token': access_token}), 200

@bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """Protected route example."""
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user}), 200