"""
Content Analyzer Module
Scans page content for phishing patterns and malicious indicators.
"""
import requests
from bs4 import BeautifulSoup
import re
import logging

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    def __init__(self):
        # Keywords that are strong indicators of phishing
        self.phishing_keywords = [
            'verify account',
            'confirm identity',
            'update payment',
            'urgent action required',
            'act now',
            'limited time',
            'unusual activity detected',
            'reset password immediately',
            'validate credentials'
        ]
        # Only look for extremely suspicious patterns (not normal JS)
        self.suspicious_patterns = [
            r'<iframe[^>]*src\s*=\s*["\']?javascript:',  # iframe with javascript: protocol
            r'eval\s*\(',  # eval() function - extremely dangerous
            r'<object[^>]*data\s*=\s*["\']?javascript:',  # object with javascript protocol
        ]
        logger.debug("ContentAnalyzer initialized with strict pattern matching")

    def check(self, url):
        """
        Analyze page content for phishing and malicious indicators.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Dictionary containing content analysis results
        """
        logger.info(f"Starting content analysis for URL: {url}")
        result = {
            'verdict': 'Safe',
            'phishing_patterns': 0,
            'malicious_scripts': 0,
            'suspicious_forms': 0,
            'spam_score': 0,
            'score': 100,
            'warnings': []
        }

        try:
            # Fetch page content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            logger.debug(f"Fetching page content from {url}...")
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            logger.debug(f"Page fetched successfully, status code: {response.status_code}")

            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            logger.debug("HTML parsed successfully")

            # Check for phishing keywords in visible text
            page_text = soup.get_text().lower()
            for keyword in self.phishing_keywords:
                if keyword in page_text:
                    result['phishing_patterns'] += 1
                    result['warnings'].append(f'Found phishing keyword: {keyword}')
                    logger.warning(f"Phishing keyword found in {url}: '{keyword}'")

            # Check for suspicious patterns in HTML
            html_content = response.text.lower()
            for pattern in self.suspicious_patterns:
                matches = len(re.findall(pattern, html_content, re.IGNORECASE))
                if matches > 0:
                    result['malicious_scripts'] += matches
                    result['warnings'].append(f'Found suspicious pattern: {pattern} ({matches} times)')
                    logger.warning(f"Suspicious pattern '{pattern}' found {matches} times in {url}")

            # Check for suspicious forms
            forms = soup.find_all('form')
            logger.debug(f"Found {len(forms)} forms in page")
            for idx, form in enumerate(forms):
                action = form.get('action', '').lower()
                # Check if form action looks suspicious
                if not action or action.startswith('javascript:'):
                    result['suspicious_forms'] += 1
                    result['warnings'].append('Form with suspicious or missing action')
                    logger.warning(f"Suspicious form #{idx+1} in {url}: action='{action}'")

            # Calculate spam score
            total_warnings = result['phishing_patterns'] + result['malicious_scripts'] + result['suspicious_forms']
            result['spam_score'] = min(100, total_warnings * 15)  # Increased multiplier since patterns are stricter
            logger.debug(f"Total warnings found: {total_warnings}, spam_score: {result['spam_score']}")

            # Determine verdict - with stricter pattern matching, be more lenient
            if total_warnings > 10:  # Increased threshold
                result['verdict'] = 'Dangerous'
                result['score'] = 10
                logger.warning(f"Content analysis verdict for {url}: DANGEROUS ({total_warnings} warnings)")
            elif total_warnings > 5:  # Increased threshold
                result['verdict'] = 'Suspicious'
                result['score'] = 50
                logger.warning(f"Content analysis verdict for {url}: SUSPICIOUS ({total_warnings} warnings)")
            else:
                result['verdict'] = 'Safe'
                result['score'] = 100
                logger.info(f"Content analysis verdict for {url}: SAFE ({total_warnings} warnings)")

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout while fetching content from {url}")
            result['error'] = 'Timeout while fetching content'
            result['verdict'] = 'Unknown'
            result['score'] = 50
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching content from {url}: {str(e)}")
            result['error'] = f'Error fetching content: {str(e)}'
            result['verdict'] = 'Unknown'
            result['score'] = 50
        except Exception as e:
            logger.error(f"Unexpected error during content analysis for {url}: {str(e)}", exc_info=True)
            result['error'] = str(e)
            result['verdict'] = 'Unknown'
            result['score'] = 50

        return result
