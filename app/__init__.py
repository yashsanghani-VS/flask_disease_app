from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from sqlalchemy import inspect
import logging
from logging.handlers import RotatingFileHandler
from app.utils.error_handler import register_error_handlers
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
bcrypt = Bcrypt()

def create_app(config_name='default'):
    app = Flask(__name__)
    
    from app.config import config
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)

    # Import all models BEFORE migrate.init_app()
    from app.models import token, user  # Add all your model files here

    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    CORS(app)

    
    # Configure logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/flask_auth.log',
                                         maxBytes=10240,
                                         backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Flask Auth startup')
    
    # Register blueprints
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    register_error_handlers(app)
    
    # Initialize database
    with app.app_context():
        db.create_all()
        
        # Only cleanup if table exists
        inspector = inspect(db.engine)
        if 'token_blacklist' in inspector.get_table_names():
            from app.models.token import TokenBlacklist
            TokenBlacklist.cleanup_expired()
    
    return app