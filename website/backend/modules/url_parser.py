"""
URL Parser Module
Extracts and validates domain, subdomain, TLD, and protocol from URLs.
"""
import re
from urllib.parse import urlparse
import tldextract
import logging

logger = logging.getLogger(__name__)


class URLParser:
    def __init__(self):
        logger.debug("URLParser initialized")
        pass

    def parse(self, url):
        """
        Parse a URL and extract components.
        
        Args:
            url (str): The URL to parse
            
        Returns:
            dict: Dictionary containing parsed URL components
        """
        try:
            logger.debug(f"Parsing URL: {url}")
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                logger.debug(f"Added https:// prefix, URL is now: {url}")

            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            result = {
                'raw_url': url,
                'protocol': parsed.scheme,
                'domain': extracted.registered_domain or extracted.domain,
                'subdomain': extracted.subdomain,
                'tld': extracted.suffix,
                'path': parsed.path,
                'query': parsed.query,
                'port': parsed.port,
                'is_valid': self._is_valid_url(url)
            }

            logger.info(f"URL parsed successfully - Domain: {result['domain']}, TLD: {result['tld']}, Valid: {result['is_valid']}")
            return result if result['is_valid'] else None

        except Exception as e:
            logger.error(f"Error parsing URL: {e}", exc_info=True)
            return None

    def _is_valid_url(self, url):
        """
        Validate URL format using regex.
        
        Args:
            url (str): The URL to validate
            
        Returns:
            bool: True if URL is valid, False otherwise
        """
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        is_valid = re.match(url_pattern, url) is not None
        logger.debug(f"URL validation result for '{url}': {is_valid}")
        return is_valid
