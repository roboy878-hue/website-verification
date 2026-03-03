"""
IP Intelligence Module
Resolves IP addresses and checks for VPN/proxy/Tor indicators.
"""
import socket
import requests
import logging

logger = logging.getLogger(__name__)


class IPIntelligence:
    def __init__(self):
        self.ip_api_url = 'https://ipapi.co/{}/json/'
        self.abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
        logger.debug("IPIntelligence initialized")

    def check(self, domain):
        """
        Get IP intelligence for a domain.
        
        Args:
            domain (str): Domain name to resolve
            
        Returns:
            dict: Dictionary containing IP information
        """
        logger.info(f"Starting IP intelligence check for domain: {domain}")
        result = {
            'status': 'Unknown',
            'ip_address': None,
            'country': 'Unknown',
            'isp': 'Unknown',
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_datacenter': False,
            'score': 50,
            'warnings': []
        }

        try:
            # Resolve domain to IP
            logger.debug(f"Resolving domain {domain} to IP address...")
            ip_address = socket.gethostbyname(domain)
            result['ip_address'] = ip_address
            logger.info(f"Domain {domain} resolved to IP: {ip_address}")

            # Check if IP is private/local
            if self._is_private_ip(ip_address):
                result['warnings'].append('Private/Local IP address')
                result['score'] = 30
                logger.warning(f"IP {ip_address} is private/local for domain {domain}")

            # Get IP information
            logger.debug(f"Fetching IP information for {ip_address}...")
            ip_info = self._get_ip_info(ip_address)
            if ip_info:
                result['country'] = ip_info.get('country_name', 'Unknown')
                result['isp'] = ip_info.get('org', 'Unknown')
                result['is_vpn'] = ip_info.get('is_vpn', False)
                result['is_proxy'] = ip_info.get('is_proxy', False)
                result['is_tor'] = ip_info.get('is_tor', False)
                result['is_datacenter'] = ip_info.get('is_datacenter', False)
                
                logger.debug(f"IP info for {ip_address}: Country={result['country']}, ISP={result['isp']}, IsVPN={result['is_vpn']}, IsProxy={result['is_proxy']}, IsTor={result['is_tor']}")

                # Adjust score based on risk factors
                if result['is_tor']:
                    result['score'] = 10
                    result['warnings'].append('Tor exit node detected')
                    logger.warning(f"Tor exit node detected for IP {ip_address}")
                elif result['is_vpn'] or result['is_proxy']:
                    result['score'] = 30
                    result['warnings'].append('VPN/Proxy detected')
                    logger.warning(f"VPN/Proxy detected for IP {ip_address}")
                elif result['is_datacenter']:
                    result['score'] = 40
                    result['warnings'].append('Hosting on datacenter IP')
                    logger.warning(f"Datacenter IP detected: {ip_address}")
                else:
                    result['score'] = 80
                    logger.info(f"IP {ip_address} appears to be regular ISP")

                result['status'] = 'Resolved'
            else:
                result['status'] = 'Resolved (Limited info)'
                result['score'] = 60
                logger.warning(f"Limited IP information available for {ip_address}")

        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for domain {domain}: {str(e)}")
            result['error'] = 'Could not resolve domain to IP'
            result['score'] = 20
        except Exception as e:
            logger.error(f"Unexpected error during IP intelligence check for {domain}: {str(e)}", exc_info=True)
            result['error'] = str(e)
            result['score'] = 50

        return result

    def _is_private_ip(self, ip_address):
        """
        Check if IP is private/local.
        """
        private_ranges = [
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '192.168.',
            '127.'
        ]
        return any(ip_address.startswith(range_prefix) for range_prefix in private_ranges)

    def _get_ip_info(self, ip_address):
        """
        Get IP information from IP API.
        """
        try:
            logger.debug(f"Calling IP API for {ip_address}...")
            response = requests.get(self.ip_api_url.format(ip_address), timeout=5)
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"IP API response for {ip_address}: {data}")
                return {
                    'country_name': data.get('country_name', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'is_vpn': False,
                    'is_proxy': False,
                    'is_tor': False,
                    'is_datacenter': data.get('is_vpn', False)
                }
        except Exception as e:
            logger.error(f"IP API error for {ip_address}: {e}")

        return None
