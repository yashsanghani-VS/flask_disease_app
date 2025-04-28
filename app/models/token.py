from datetime import datetime, timedelta
from app import db

class TokenBlacklist(db.Model):
    """Model for storing blacklisted JWT tokens."""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, jti, created_at=None):
        self.jti = jti
        self.created_at = created_at or datetime.utcnow()
        self.expires = self.created_at + timedelta(days=1)  # Tokens expire after 1 day
    
    @classmethod
    def is_blacklisted(cls, jti):
        """Check if token is blacklisted."""
        return bool(cls.query.filter_by(jti=jti).first())
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired tokens from blacklist."""
        cls.query.filter(cls.expires < datetime.utcnow()).delete()
        db.session.commit()