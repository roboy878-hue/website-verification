from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

# Note: db is created in app.py and imported here
# This will be set up after Flask app initialization
db = None


def init_db(db_instance):
    """Initialize the database instance"""
    global db
    db = db_instance


class User(db.Model):
    """User model for storing user information"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    verification_requests = db.relationship('VerificationRequest', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'


class URL(db.Model):
    """URL model for storing website information"""
    __tablename__ = 'urls'

    id = db.Column(db.Integer, primary_key=True)
    raw_url = db.Column(db.String(500), nullable=False)
    domain = db.Column(db.String(255), nullable=False, unique=True)
    tld = db.Column(db.String(50))
    protocol = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    verification_requests = db.relationship('VerificationRequest', backref='url', lazy=True)
    ssl_certificate = db.relationship('SSLCertificate', backref='url', uselist=False)
    domain_info = db.relationship('DomainInfo', backref='url', uselist=False)
    content_analysis = db.relationship('ContentAnalysis', backref='url', uselist=False)
    ip_info = db.relationship('IPInfo', backref='url', uselist=False)
    reputation_score = db.relationship('ReputationScore', backref='url', uselist=False)

    def __repr__(self):
        return f'<URL {self.domain}>'


class VerificationRequest(db.Model):
    """Verification request model for tracking user requests"""
    __tablename__ = 'verification_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    verdict = db.Column(db.String(50))  # Genuine, Suspicious, Malicious
    trust_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    report = db.relationship('Report', backref='verification_request', uselist=False)

    def __repr__(self):
        return f'<VerificationRequest {self.id}>'


class SSLCertificate(db.Model):
    """SSL Certificate model"""
    __tablename__ = 'ssl_certificates'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    issuer = db.Column(db.String(255))
    valid = db.Column(db.Boolean)
    self_signed = db.Column(db.Boolean)
    expiry_date = db.Column(db.DateTime)
    status = db.Column(db.String(50))
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<SSLCertificate {self.url_id}>'


class DomainInfo(db.Model):
    """Domain WHOIS information"""
    __tablename__ = 'domain_info'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    registrar = db.Column(db.String(255))
    registration_date = db.Column(db.DateTime)
    expiry_date = db.Column(db.DateTime)
    domain_age_days = db.Column(db.Integer)
    registrant_country = db.Column(db.String(50))
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<DomainInfo {self.url_id}>'


class BlacklistCheck(db.Model):
    """Blacklist check results"""
    __tablename__ = 'blacklist_checks'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'))
    source = db.Column(db.String(100))  # VirusTotal, Google Safe Browsing, PhishTank
    threat_type = db.Column(db.String(100))
    is_listed = db.Column(db.Boolean)
    severity = db.Column(db.String(50))
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<BlacklistCheck {self.source}>'


class ContentAnalysis(db.Model):
    """Content analysis results"""
    __tablename__ = 'content_analysis'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    phishing_patterns_found = db.Column(db.Integer, default=0)
    malicious_scripts = db.Column(db.Integer, default=0)
    suspicious_forms = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(50))
    spam_score = db.Column(db.Float)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ContentAnalysis {self.url_id}>'


class IPInfo(db.Model):
    """IP address intelligence"""
    __tablename__ = 'ip_info'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    ip_address = db.Column(db.String(50))
    isp = db.Column(db.String(255))
    country = db.Column(db.String(100))
    is_vpn = db.Column(db.Boolean, default=False)
    is_proxy = db.Column(db.Boolean, default=False)
    is_tor = db.Column(db.Boolean, default=False)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IPInfo {self.ip_address}>'


class ReputationScore(db.Model):
    """Aggregated reputation scores"""
    __tablename__ = 'reputation_scores'

    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    blacklist_score = db.Column(db.Float)
    ssl_score = db.Column(db.Float)
    domain_age_score = db.Column(db.Float)
    content_score = db.Column(db.Float)
    ip_score = db.Column(db.Float)
    final_trust_score = db.Column(db.Float)
    trust_level = db.Column(db.String(50))
    verdict = db.Column(db.String(50))
    calculated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ReputationScore {self.url_id}>'


class Report(db.Model):
    """Generated verification reports"""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    verification_request_id = db.Column(db.Integer, db.ForeignKey('verification_requests.id'), nullable=False)
    url = db.Column(db.String(500))
    verdict = db.Column(db.String(50))
    trust_score = db.Column(db.Float)
    details = db.Column(db.Text)  # JSON string
    recommendations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Report {self.id}>'
