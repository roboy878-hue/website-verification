"""
Score Engine Module
Aggregates module results with weighted scoring and determines final verdict.
"""
import logging

logger = logging.getLogger(__name__)


class ScoreEngine:
    def __init__(self):
        # Scoring weights as per project specification
        self.weights = {
            'blacklist': 0.35,      # 35% - strongest signal
            'ssl': 0.20,            # 20% - certificate validity
            'domain_age': 0.20,     # 20% - domain longevity
            'content': 0.15,        # 15% - phishing patterns
            'ip': 0.10              # 10% - IP intelligence
        }
        logger.debug(f"ScoreEngine initialized with weights: {self.weights}")

    def calculate(self, results):
        """
        Calculate weighted trust score and determine verdict.
        
        Args:
            results (dict): Dictionary containing scores from all modules
                {
                    'blacklist': {...},
                    'ssl': {...},
                    'whois': {...},
                    'content': {...},
                    'ip': {...}
                }
                
        Returns:
            dict: Dictionary containing final score and verdict
        """
        try:
            logger.info("[SCORE ENGINE] Starting score calculation...")
            logger.debug(f"Input results: {results}")
            
            # Extract scores from each module
            blacklist_score = results.get('blacklist', {}).get('score', 50)
            ssl_score = results.get('ssl', {}).get('score', 50)
            domain_age_score = results.get('whois', {}).get('score', 50)
            content_score = results.get('content', {}).get('score', 50)
            ip_score = results.get('ip', {}).get('score', 50)
            
            logger.debug(f"[SCORE ENGINE] Extracted component scores - Blacklist: {blacklist_score}, SSL: {ssl_score}, Domain Age: {domain_age_score}, Content: {content_score}, IP: {ip_score}")

            # Calculate weighted overall score
            final_score = (
                (blacklist_score * self.weights['blacklist']) +
                (ssl_score * self.weights['ssl']) +
                (domain_age_score * self.weights['domain_age']) +
                (content_score * self.weights['content']) +
                (ip_score * self.weights['ip'])
            )

            # Round to nearest integer
            final_score = round(final_score, 2)
            logger.debug(f"[SCORE ENGINE] Weighted calculation: ({blacklist_score} × {self.weights['blacklist']}) + ({ssl_score} × {self.weights['ssl']}) + ({domain_age_score} × {self.weights['domain_age']}) + ({content_score} × {self.weights['content']}) + ({ip_score} × {self.weights['ip']}) = {final_score}")

            # Determine verdict and trust level
            verdict, trust_level = self._determine_verdict(final_score, results)
            logger.info(f"[SCORE ENGINE] Final score: {final_score}, Verdict: {verdict}, Trust Level: {trust_level}")

            result = {
                'score': final_score,
                'verdict': verdict,
                'trust_level': trust_level,
                'component_scores': {
                    'blacklist': blacklist_score,
                    'ssl': ssl_score,
                    'domain_age': domain_age_score,
                    'content': content_score,
                    'ip': ip_score
                },
                'weights': self.weights
            }

            return result

        except Exception as e:
            logger.error(f"[SCORE ENGINE] Error during score calculation: {str(e)}", exc_info=True)
            return {
                'score': 50,
                'verdict': 'Unknown',
                'trust_level': 'Unverified',
                'error': str(e)
            }

    def _determine_verdict(self, score, results):
        """
        Determine verdict and trust level based on score and module results.
        
        Args:
            score (float): Final weighted score
            results (dict): All module results for context
            
        Returns:
            tuple: (verdict, trust_level)
        """
        logger.debug(f"[VERDICT LOGIC] Determining verdict for score: {score}")
        
        # Check for critical issues that override score
        blacklist_result = results.get('blacklist', {})
        ssl_result = results.get('ssl', {})

        # If URL is in blacklist, it's definitely malicious
        if blacklist_result.get('is_malicious'):
            logger.warning(f"[VERDICT LOGIC] URL is in blacklist - overriding to MALICIOUS")
            return ('Malicious', 'Dangerous')

        # If SSL is invalid/missing, lower trust
        if ssl_result.get('score', 100) == 0:
            if score < 30:
                logger.warning(f"[VERDICT LOGIC] SSL invalid and low score ({score}) - overriding to MALICIOUS")
                return ('Malicious', 'Dangerous')

        # Determine verdict based on score
        if score >= 80:
            logger.info(f"[VERDICT LOGIC] Score {score} >= 80 → GENUINE")
            return ('Genuine', 'Safe')
        elif score >= 50:
            logger.warning(f"[VERDICT LOGIC] Score {score} >= 50 but < 80 → SUSPICIOUS")
            return ('Suspicious', 'Caution')
        else:
            logger.error(f"[VERDICT LOGIC] Score {score} < 50 → MALICIOUS")
            return ('Malicious', 'Dangerous')
