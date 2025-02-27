from flask import Flask
from app.config import config
from app.auth.models import db
from app.auth.routes import limiter
from flask_cors import CORS

def create_app(config_name='default'):
    """Application factory function."""
    app = Flask(__name__)
    CORS(app)

    # Load config
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    limiter.init_app(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Register blueprints
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return {'status': 'healthy'}, 200
    
    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)