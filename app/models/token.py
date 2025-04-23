from app import db
from datetime import datetime

class TokenBlacklist(db.Model):
    """Model for storing blacklisted JWT tokens."""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    token_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires = db.Column(db.DateTime, nullable=False)
    
    def __init__(self, jti, token_type, user_id, expires):
        self.jti = jti
        self.token_type = token_type
        self.user_id = user_id
        self.expires = expires
    
    @classmethod
    def is_blacklisted(cls, jti):
        """Check if token is blacklisted."""
        return bool(cls.query.filter_by(jti=jti).first())
    
    @classmethod
    def add(cls, jti, token_type, user_id, expires):
        """Add token to blacklist."""
        blacklisted_token = cls(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires=expires
        )
        db.session.add(blacklisted_token)
        db.session.commit()
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired tokens from blacklist."""
        cls.query.filter(cls.expires < datetime.utcnow()).delete()
        db.session.commit()