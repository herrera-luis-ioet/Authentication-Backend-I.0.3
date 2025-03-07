from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from flask import current_app
from typing import Dict, Optional

db = SQLAlchemy()

# PUBLIC_INTERFACE
class User(db.Model):
    """
    User model for authentication system.
    
    This class represents a user in the authentication system and provides methods
    for password management and JWT token generation. It stores user credentials
    and handles authentication-related operations.
    
    Attributes:
        id (int): Primary key for the user record
        username (str): Unique username for the user
        password_hash (str): Hashed password for secure storage
        
    Examples:
        Creating a new user:
        >>> user = User(username='johndoe')
        >>> user.set_password('secure_password123')
        >>> db.session.add(user)
        >>> db.session.commit()
        
        Authenticating a user:
        >>> user = User.get_by_username('johndoe')
        >>> if user and user.check_password('secure_password123'):
        ...     tokens = user.generate_tokens()
        ...     # Use tokens for authentication
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username: str, password: str):
        """
        Initialize a new User instance.
        
        Creates a new user with the specified username and password.
        The password is automatically hashed during initialization.
        
        Args:
            username (str): The username for the new user
            password (str): The plaintext password for the new user
            
        Returns:
            None
            
        Examples:
            >>> user = User('johndoe', 'secure_password123')
            >>> db.session.add(user)
            >>> db.session.commit()
        """
        self.username = username
        self.set_password(password)

    def set_password(self, password: str) -> None:
        """
        Hash and set the user's password.
        
        Takes a plaintext password, generates a secure hash, and stores it in
        the password_hash field. This ensures that the actual password is never
        stored in the database.
        
        Args:
            password (str): The plaintext password to hash and store
            
        Returns:
            None
            
        Examples:
            >>> user = User.get_by_username('johndoe')
            >>> user.set_password('new_secure_password')
            >>> db.session.commit()
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify if the provided password matches the stored hash.
        
        Compares the provided plaintext password against the stored hash
        to authenticate the user.
        
        Args:
            password (str): The plaintext password to check
            
        Returns:
            bool: True if the password matches, False otherwise
            
        Examples:
            >>> user = User.get_by_username('johndoe')
            >>> if user.check_password('entered_password'):
            ...     print("Authentication successful")
            ... else:
            ...     print("Authentication failed")
        """
        return check_password_hash(self.password_hash, password)

    def generate_tokens(self) -> Dict[str, str]:
        """
        Generate JWT access and refresh tokens for the user.
        
        Creates two JWT tokens:
        1. An access token with a short expiration time (15 minutes) for API access
        2. A refresh token with a longer expiration time (30 days) for obtaining new access tokens
        
        Returns:
            Dict[str, str]: A dictionary containing the access_token and refresh_token
            
        Raises:
            Exception: If there's an error during token generation
            
        Examples:
            >>> user = User.get_by_username('johndoe')
            >>> tokens = user.generate_tokens()
            >>> access_token = tokens['access_token']
            >>> refresh_token = tokens['refresh_token']
        """
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
        """
        Retrieve a user by their username.
        
        Queries the database to find a user with the specified username.
        
        Args:
            username (str): The username to search for
            
        Returns:
            Optional[User]: The user object if found, None otherwise
            
        Examples:
            >>> user = User.get_by_username('johndoe')
            >>> if user:
            ...     print(f"Found user with ID: {user.id}")
            ... else:
            ...     print("User not found")
        """
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_by_id(user_id: int) -> Optional['User']:
        """
        Retrieve a user by their ID.
        
        Queries the database to find a user with the specified ID.
        
        Args:
            user_id (int): The user ID to search for
            
        Returns:
            Optional[User]: The user object if found, None otherwise
            
        Examples:
            >>> user = User.get_by_id(42)
            >>> if user:
            ...     print(f"Found user: {user.username}")
            ... else:
            ...     print("User not found")
        """
        return User.query.get(user_id)
