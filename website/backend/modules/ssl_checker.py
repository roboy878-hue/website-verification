"""
SSL Certificate Checker Module
Validates SSL certificates for domains.
"""
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
import logging

logger = logging.getLogger(__name__)


class SSLChecker:
    def __init__(self):
        logger.debug("SSLChecker initialized")
        pass

    def check(self, domain):
        """
        Check SSL certificate validity for a domain.
        
        Args:
            domain (str): Domain name to check
            
        Returns:
            dict: Dictionary containing SSL check results
        """
        logger.info(f"Starting SSL certificate check for domain: {domain}")
        try:
            context = ssl.create_default_context()
            logger.debug(f"Connecting to {domain}:443 for SSL check...")
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_bin = ssock.getpeercert(binary_form=True)
                    logger.debug(f"SSL certificate retrieved for {domain}")

                    # Parse certificate
                    cert_obj = x509.load_der_x509_certificate(cert_bin)

                    # Extract issuer
                    issuer = cert_obj.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    issuer_name = issuer[0].value if issuer else 'Unknown'

                    # Check expiry
                    expiry_date = cert_obj.not_valid_after
                    is_expired = expiry_date < datetime.utcnow()

                    # Check if self-signed
                    is_self_signed = cert_obj.issuer == cert_obj.subject

                    result = {
                        'status': 'Valid' if not is_expired and not is_self_signed else ('Expired' if is_expired else 'Self-Signed'),
                        'issuer': issuer_name,
                        'expiry_date': expiry_date.isoformat(),
                        'is_expired': is_expired,
                        'is_self_signed': is_self_signed,
                        'score': 100 if (not is_expired and not is_self_signed) else 30
                    }
                    
                    logger.info(f"SSL check completed for {domain}: Status={result['status']}, Score={result['score']}")

        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {str(e)}")
            result = {
                'status': 'Invalid or Missing',
                'error': str(e),
                'issuer': 'N/A',
                'expiry_date': None,
                'is_expired': True,
                'is_self_signed': False,
                'score': 0
            }
        except socket.timeout:
            logger.warning(f"Socket timeout while checking SSL for {domain}")
            result = {
                'status': 'Timeout',
                'error': 'Connection timeout',
                'score': 20
            }
        except Exception as e:
            logger.error(f"Unexpected error during SSL check for {domain}: {str(e)}", exc_info=True)
            result = {
                'status': 'Error',
                'error': str(e),
                'score': 20
            }

        return result
