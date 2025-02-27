from flask import Flask
from flask_jwt_extended import JWTManager
from app.config import config

jwt = JWTManager()

def create_app(config_name='default'):
    """Application factory function."""
    app = Flask(__name__)
    
    # Load config
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    jwt.init_app(app)
    
    # Register blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    
    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return {'status': 'healthy'}, 200
    
    return app