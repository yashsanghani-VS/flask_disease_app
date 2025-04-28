import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(name, log_file='app.log', level=logging.INFO):
    """Setup and return a logger with the specified name."""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create formatters
    console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]')
    
    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    
    file_handler = RotatingFileHandler(
        f'logs/{log_file}',
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(file_formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# Create a default logger instance
logger = setup_logger('flask_app') 