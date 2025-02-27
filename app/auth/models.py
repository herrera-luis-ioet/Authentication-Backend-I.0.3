import bcrypt
from typing import Optional, Dict

class User:
    """User model for authentication."""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password_hash = self._hash_password(password)
    
    @staticmethod
    def _hash_password(password: str) -> bytes:
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    def check_password(self, password: str) -> bool:
        """Check if the provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)
    
    def to_dict(self) -> Dict[str, str]:
        """Convert user object to dictionary."""
        return {
            'username': self.username
        }
    
    @classmethod
    def get_by_username(cls, username: str) -> Optional['User']:
        """
        Get user by username.
        This is a placeholder method - in a real application, 
        this would query a database.
        """
        # TODO: Implement database integration
        return None