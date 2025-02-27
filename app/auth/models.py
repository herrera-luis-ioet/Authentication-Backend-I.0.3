from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from flask import current_app
from typing import Dict, Optional

db = SQLAlchemy()

# PUBLIC_INTERFACE
class User(db.Model):
    """User model for authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username: str, password: str):
        """Initialize a new user."""
        self.username = username
        self.set_password(password)

    def set_password(self, password: str) -> None:
        """Hash and set the user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)

    def generate_tokens(self) -> Dict[str, str]:
        """Generate access and refresh tokens for the user."""
        access_token = jwt.encode(
            {
                'user_id': self.id,
                'exp': datetime.utcnow() + timedelta(minutes=15)
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        refresh_token = jwt.encode(
            {
                'user_id': self.id,
                'exp': datetime.utcnow() + timedelta(days=30)
            },
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

    @staticmethod
    def get_by_username(username: str) -> Optional['User']:
        """Get a user by their username."""
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_by_id(user_id: int) -> Optional['User']:
        """Get a user by their ID."""
        return User.query.get(user_id)