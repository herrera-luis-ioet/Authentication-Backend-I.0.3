from flask_cors import CORS
from flask import Flask, cli
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from app.config import Config

db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)

def create_app(config_class=Config):
    app = Flask(__name__)
    CORS(app)

    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    @app.route('/health')
    def health_check():
        """Health check endpoint."""
        return {'status': 'healthy'}, 200

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)