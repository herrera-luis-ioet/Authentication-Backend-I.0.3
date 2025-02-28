import pytest
import os
from app.auth.models import db, User
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError, IntegrityError
import time

def test_sqlite_connection(app):
    """Test SQLite database connection and basic operations."""
    with app.app_context():
        # Verify we can create and query users
        user = User(username='sqlite_test', password='Test@123')
        db.session.add(user)
        db.session.commit()
        
        # Query the user back
        queried_user = User.query.filter_by(username='sqlite_test').first()
        assert queried_user is not None
        assert queried_user.username == 'sqlite_test'
        
        # Test transaction rollback
        try:
            # Try to create a user with duplicate username
            duplicate_user = User(username='sqlite_test', password='Test@123')
            db.session.add(duplicate_user)
            db.session.commit()
            assert False, "Should have raised an integrity error"
        except IntegrityError:
            db.session.rollback()
            assert True

@pytest.mark.mysql_required
def test_mysql_connection(app, mysql_connection_params):
    """Test MySQL database connection and basic operations."""
    with app.app_context():
        # Verify we can create and query users
        user = User(username='mysql_test', password='Test@123')
        db.session.add(user)
        db.session.commit()
        
        # Query the user back
        queried_user = User.query.filter_by(username='mysql_test').first()
        assert queried_user is not None
        assert queried_user.username == 'mysql_test'
        
        # Test UTF-8 support
        utf8_user = User(username='\u6d4b\u8bd5\u7528\u6237', password='Test@123')
        db.session.add(utf8_user)
        db.session.commit()
        
        # Query the UTF-8 user back
        queried_utf8_user = User.query.filter_by(username='\u6d4b\u8bd5\u7528\u6237').first()
        assert queried_utf8_user is not None
        assert queried_utf8_user.username == '\u6d4b\u8bd5\u7528\u6237'

@pytest.mark.mysql_required
def test_data_migration(app, mysql_connection_params):
    """Test data migration between SQLite and MySQL backends."""
    # Create a temporary SQLite database
    sqlite_path = 'test_migration.db'
    sqlite_uri = f'sqlite:///{sqlite_path}'
    
    # MySQL connection parameters from fixture
    mysql_uri = 'mysql+pymysql://{}:{}@{}:{}/{}'.format(
        mysql_connection_params['user'],
        mysql_connection_params['password'],
        mysql_connection_params['host'],
        mysql_connection_params['port'],
        mysql_connection_params['database']
    )
    
    try:
        # Set up SQLite source database
        sqlite_engine = create_engine(sqlite_uri)
        with app.app_context():
            db.Model.metadata.create_all(sqlite_engine)
        
        # Create test data in SQLite
        Session = sessionmaker(bind=sqlite_engine)
        sqlite_session = Session()
        test_users = [
            User(username=f'migrate_user_{i}', password=f'Test@123_{i}')
            for i in range(3)
        ]
        for user in test_users:
            sqlite_session.add(user)
        sqlite_session.commit()
        
        # Get user data from SQLite
        sqlite_users = sqlite_session.query(User).all()
        user_data = [
            {
                'username': user.username,
                'password_hash': user.password_hash
            }
            for user in sqlite_users
        ]
        sqlite_session.close()
        
        # Set up MySQL target database
        mysql_engine = create_engine(
            mysql_uri,
            pool_size=10,
            max_overflow=5,
            pool_timeout=30,
            pool_recycle=3600
        )
        with app.app_context():
            db.Model.metadata.create_all(mysql_engine)
        
        # Migrate data to MySQL
        mysql_session = sessionmaker(bind=mysql_engine)()
        for user_info in user_data:
            user = User(
                username=user_info['username'],
                password_hash=user_info['password_hash']
            )
            mysql_session.add(user)
        mysql_session.commit()
        
        # Verify data in MySQL
        migrated_users = mysql_session.query(User).all()
        assert len(migrated_users) == len(test_users)
        
        for original, migrated in zip(
            sorted(user_data, key=lambda x: x['username']),
            sorted(migrated_users, key=lambda x: x.username)
        ):
            assert original['username'] == migrated.username
            assert original['password_hash'] == migrated.password_hash
        
        mysql_session.close()
        
    finally:
        # Cleanup
        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)

@pytest.mark.mysql_required
def test_connection_pool(app, mysql_connection_params):
    """Test MySQL connection pool handling."""
    with app.app_context():
        # Test multiple concurrent connections
        sessions = []
        try:
            # Create multiple sessions
            for i in range(5):
                session = db.create_scoped_session()
                sessions.append(session)
                
                # Verify each session works
                user = User(username=f'pool_test_{i}', password='Test@123')
                session.add(user)
                session.commit()
                
                # Query to verify
                queried_user = session.query(User).filter_by(
                    username=f'pool_test_{i}'
                ).first()
                assert queried_user is not None
                
        finally:
            # Cleanup sessions
            for session in sessions:
                session.remove()

@pytest.mark.mysql_required
def test_connection_timeout_handling(app, mysql_connection_params):
    """Test MySQL connection timeout handling."""
    with app.app_context():
        # Test connection recovery after timeout
        try:
            # Create initial connection
            user = User(username='timeout_test_1', password='Test@123')
            db.session.add(user)
            db.session.commit()
            
            # Simulate timeout by waiting
            time.sleep(2)
            
            # Try another operation (should reconnect automatically)
            user = User(username='timeout_test_2', password='Test@123')
            db.session.add(user)
            db.session.commit()
            
            # Verify both operations succeeded
            users = User.query.filter(
                User.username.like('timeout_test_%')
            ).all()
            assert len(users) == 2
            
        except OperationalError as e:
            assert False, f"Connection handling failed: {str(e)}"

@pytest.mark.mysql_required
def test_connection_error_handling(app, mysql_connection_params):
    """Test handling of MySQL connection errors."""
    with app.app_context():
        # Test automatic reconnection
        try:
            # Force connection pool to be cleared
            db.engine.dispose()
            
            # Should automatically reconnect
            user = User(username='reconnect_test', password='Test@123')
            db.session.add(user)
            db.session.commit()
            
            # Verify operation succeeded
            queried_user = User.query.filter_by(username='reconnect_test').first()
            assert queried_user is not None
            
        except OperationalError as e:
            assert False, f"Error handling failed: {str(e)}"

@pytest.mark.mysql_required
def test_mysql_charset_handling(app, mysql_connection_params):
    """Test MySQL character set handling."""
    with app.app_context():
        try:
            # Test inserting and retrieving data with special characters
            special_chars = "特殊字符测试 - áéíóú ñ"
            user = User(username=special_chars, password='Test@123')
            db.session.add(user)
            db.session.commit()
            
            # Query back and verify
            queried_user = User.query.filter_by(username=special_chars).first()
            assert queried_user is not None
            assert queried_user.username == special_chars
            
            # Verify database connection charset
            result = db.session.execute(text("SHOW VARIABLES LIKE 'character_set_connection'"))
            charset = result.fetchone()
            assert charset[1] == 'utf8mb4', "Database connection should use utf8mb4 charset"
            
        except Exception as e:
            assert False, f"Character set handling failed: {str(e)}"