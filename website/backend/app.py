from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables
load_dotenv()

# ===== Setup Logging =====
def setup_logging():
    """Configure logging for the application"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure logging format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    
    # Console handler (for terminal output)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    # File handler (for file output with rotation)
    file_handler = RotatingFileHandler('logs/verification.log', maxBytes=10485760, backupCount=10)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(log_format))
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    return logging.getLogger(__name__)

# Initialize logging
logger = setup_logging()
logger.info("="*80)
logger.info("Website Genuineness Verification System - Logger Initialized")
logger.info("="*80)

# Initialize Flask app
app = Flask(__name__)
logger.debug("Flask app initialized")

# Try to handle CORS if available
try:
    from flask_cors import CORS
    CORS(app)
    logger.info("CORS enabled")
except ImportError:
    logger.warning("Flask-CORS not installed, CORS disabled")
    pass

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///verification.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
logger.info(f"Database configured: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Initialize database
db = SQLAlchemy(app)
logger.debug("Database initialized")


# ===== Database Models =====

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

    def __repr__(self):
        return f'<URL {self.domain}>'


class VerificationRequest(db.Model):
    """Verification request model for tracking user requests"""
    __tablename__ = 'verification_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    verdict = db.Column(db.String(50))
    trust_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    report = db.relationship('Report', backref='verification_request', uselist=False)

    def __repr__(self):
        return f'<VerificationRequest {self.id}>'


class Report(db.Model):
    """Generated verification reports"""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    verification_request_id = db.Column(db.Integer, db.ForeignKey('verification_requests.id'), nullable=False)
    url = db.Column(db.String(500))
    verdict = db.Column(db.String(50))
    trust_score = db.Column(db.Float)
    details = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Report {self.id}>'


# ===== Import verification modules =====
from modules.url_parser import URLParser
from modules.ssl_checker import SSLChecker
from modules.whois_lookup import WHOISLookup
from modules.blacklist_check import BlacklistCheck
from modules.content_analyzer import ContentAnalyzer
from modules.ip_intelligence import IPIntelligence
from modules.score_engine import ScoreEngine


@app.route('/')
def index():
    """
    Health check endpoint - confirms the backend is running.
    """
    return jsonify({"status": "Backend is running!", "timestamp": datetime.now().isoformat()})


@app.route('/verify', methods=['POST'])
def verify_url():
    """
    Main endpoint for URL verification.
    Accepts JSON with 'url' field and returns verification report.
    """
    try:
        data = request.get_json()
        url = data.get('url')
        
        logger.info(f"[VERIFY REQUEST] Starting verification for URL: {url}")

        if not url:
            logger.error("[VERIFY REQUEST] URL is required but not provided")
            return jsonify({"error": "URL is required"}), 400

        # Initialize verification modules
        url_parser = URLParser()
        ssl_checker = SSLChecker()
        whois_lookup = WHOISLookup()
        blacklist_check = BlacklistCheck()
        content_analyzer = ContentAnalyzer()
        ip_intelligence = IPIntelligence()
        score_engine = ScoreEngine()
        logger.debug("All verification modules initialized")

        # Step 1: Parse URL
        logger.info("[STEP 1] Parsing URL...")
        parsed_url = url_parser.parse(url)
        if not parsed_url:
            logger.error(f"[STEP 1] Failed to parse URL: {url}")
            return jsonify({"error": "Invalid URL format"}), 400
        logger.info(f"[STEP 1] URL parsed successfully: {parsed_url}")

        # Step 2: Run all verification checks
        logger.info("[STEP 2] Running verification checks...")
        
        logger.info("[CHECK] Starting SSL Certificate check...")
        ssl_result = ssl_checker.check(parsed_url['domain'])
        logger.info(f"[CHECK] SSL result: {ssl_result}")
        
        logger.info("[CHECK] Starting WHOIS/Domain Age check...")
        whois_result = whois_lookup.check(parsed_url['domain'])
        logger.info(f"[CHECK] WHOIS result: {whois_result}")
        
        logger.info("[CHECK] Starting Blacklist check...")
        blacklist_result = blacklist_check.check(url)
        logger.info(f"[CHECK] Blacklist result: {blacklist_result}")
        
        logger.info("[CHECK] Starting Content Analysis...")
        content_result = content_analyzer.check(url)
        logger.info(f"[CHECK] Content Analysis result: {content_result}")
        
        logger.info("[CHECK] Starting IP Intelligence check...")
        ip_result = ip_intelligence.check(parsed_url['domain'])
        logger.info(f"[CHECK] IP Intelligence result: {ip_result}")

        # Step 3: Aggregate results and calculate score
        logger.info("[STEP 3] Aggregating results and calculating score...")
        all_results = {
            'ssl': ssl_result,
            'whois': whois_result,
            'blacklist': blacklist_result,
            'content': content_result,
            'ip': ip_result
        }

        score_result = score_engine.calculate(all_results)
        logger.info(f"[STEP 3] Score calculation complete: {score_result}")

        # Step 4: Build response
        logger.info("[STEP 4] Building response...")
        report = {
            "url": url,
            "domain": parsed_url.get('domain'),
            "trust_score": score_result['score'],
            "trust_level": score_result['trust_level'],
            "verdict": score_result['verdict'],
            "details": {
                "ssl_check": ssl_result.get('status', 'Unknown'),
                "domain_age": whois_result.get('domain_age', 'Unknown'),
                "blacklist_status": blacklist_result.get('status', 'Not checked'),
                "content_analysis": content_result.get('verdict', 'Not checked'),
                "ip_info": ip_result.get('country', 'Unknown')
            },
            "component_scores": score_result.get('component_scores', {}),
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"[VERIFY REQUEST] Verification completed successfully. Final verdict: {report['verdict']} (Score: {report['trust_score']})")
        return jsonify(report), 200

    except Exception as e:
        logger.error(f"[VERIFY REQUEST] Error during verification: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/report/<int:report_id>', methods=['GET'])
def get_report(report_id):
    """
    Retrieve a stored verification report by ID.
    """
    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        return jsonify({
            "id": report.id,
            "url": report.url,
            "verdict": report.verdict,
            "trust_score": report.trust_score,
            "details": report.details,
            "created_at": report.created_at.isoformat()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/history', methods=['GET'])
def get_history():
    """
    Retrieve verification history (all stored reports).
    """
    try:
        reports = Report.query.order_by(Report.created_at.desc()).all()
        return jsonify([{
            "id": report.id,
            "url": report.url,
            "verdict": report.verdict,
            "trust_score": report.trust_score,
            "created_at": report.created_at.isoformat()
        } for report in reports]), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint.
    """
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()}), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Running the app on port 5000 in debug mode
    app.run(host='0.0.0.0', port=5000, debug=True)
