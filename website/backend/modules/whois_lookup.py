"""
WHOIS Lookup Module
Retrieves domain registration information and calculates domain age.
"""
import whois
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class WHOISLookup:
    def __init__(self):
        logger.debug("WHOISLookup initialized")
        pass

    def check(self, domain):
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain (str): Domain name to lookup
            
        Returns:
            dict: Dictionary containing domain information
        """
        logger.info(f"Starting WHOIS lookup for domain: {domain}")
        try:
            domain_info = whois.whois(domain)
            logger.debug(f"WHOIS data retrieved for {domain}")

            # Extract registration and expiry dates
            creation_date = domain_info.creation_date
            expiry_date = domain_info.expiration_date

            # Handle cases where dates might be lists
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0] if expiry_date else None

            # Calculate domain age
            if creation_date:
                domain_age = datetime.now() - creation_date
                domain_age_days = domain_age.days
                logger.debug(f"Domain {domain} created on {creation_date}, age: {domain_age_days} days")
            else:
                domain_age_days = 0
                logger.warning(f"Could not determine creation date for {domain}")

            # Calculate age score
            score = self._calculate_age_score(domain_age_days)

            result = {
                'status': 'Found',
                'registrar': domain_info.registrar or 'Unknown',
                'creation_date': creation_date.isoformat() if creation_date else None,
                'expiry_date': expiry_date.isoformat() if expiry_date else None,
                'domain_age': f"{domain_age_days} days",
                'domain_age_days': domain_age_days,
                'is_expired': expiry_date < datetime.now() if expiry_date else False,
                'score': score
            }
            
            logger.info(f"WHOIS lookup completed for {domain}: Age={domain_age_days} days, Score={score}")

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {str(e)}", exc_info=True)
            result = {
                'status': 'Not Found or Error',
                'error': str(e),
                'domain_age': 'Unknown',
                'domain_age_days': 0,
                'score': 30
            }

        return result

    def _calculate_age_score(self, domain_age_days):
        """
        Calculate score based on domain age.
        Newer domains are riskier.
        
        Args:
            domain_age_days (int): Age of domain in days
            
        Returns:
            int: Score between 0 and 100
        """
        if domain_age_days < 30:  # Less than 1 month
            score = 20
            logger.debug(f"Domain age {domain_age_days} days: Very new domain (score: 20)")
        elif domain_age_days < 365:  # Less than 1 year
            score = 50
            logger.debug(f"Domain age {domain_age_days} days: Less than 1 year (score: 50)")
        elif domain_age_days < 1825:  # Less than 5 years
            score = 75
            logger.debug(f"Domain age {domain_age_days} days: 1-5 years old (score: 75)")
        else:  # 5+ years
            score = 100
            logger.debug(f"Domain age {domain_age_days} days: 5+ years old (score: 100)")
        
        return score
