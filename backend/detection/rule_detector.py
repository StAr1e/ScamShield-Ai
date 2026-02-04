import re
from typing import Dict, List

class RuleDetector:
    """Rule-based scam pattern detection"""
    
    def __init__(self, rules_path: str = None):
        """Initialize rule detector"""
        self.rules_path = rules_path
        self._load_rules()
    
    def _load_rules(self):
        """Load detection rules"""
        # Pakistan + Global brands
        self.BRANDS = {
            'pakistan_financial': [
                r'\beasypaisa\b', r'\bjazzcash\b', r'\bhbl\b', r'\bubl\b',
                r'\bmeezan\b', r'\bally\b', r'\bfaysal\b', r'\bhabib\b'
            ],
            'global_financial': [
                r'\bpaypal\b', r'\bstripe\b', r'\bwestern union\b'
            ],
            'global_tech': [
                r'\bwhatsapp\b', r'\bgoogle\b', r'\bamazon\b'
            ],
            'government': [
                r'\bfbr\b', r'\bnadra\b', r'\birs\b'
            ]
        }
        
        self.URGENCY_KEYWORDS = [
            r'\burgent(ly)?\b', r'\bimmediately\b', r'\basap\b',
            r'\bnow\b', r'\btoday\b', r'\bexpir(e|ing|ed)\b'
        ]
        
        self.SENSITIVE_DATA = [
            r'\botp\b', r'\bpin\b', r'\bpassword\b', r'\bcvv\b', r'\bcnic\b'
        ]
        
        self.EXPLANATIONS = {
            'brand_impersonation_pakistan_financial': '🏦 Pakistan Financial Brand: Easypaisa/JazzCash mentioned',
            'brand_impersonation_global_financial': '💳 Global Payment Service: PayPal/Stripe mentioned',
            'brand_impersonation_global_tech': '🌐 Tech Giant: WhatsApp/Google/Amazon mentioned',
            'brand_impersonation_government': '🏛️ Government Entity: FBR/NADRA mentioned',
            'urgency_language': '⏰ Urgency Pressure: Time-sensitive language detected',
            'sensitive_data_request': '🔐 Critical Data Request: Asking for OTP/PIN/Password',
            'shortened_url': '🔗 Shortened URL: bit.ly/tinyurl detected'
        }
    
    def analyze(self, message: str, lang_info: Dict) -> Dict:
        """Analyze message using rules"""
        text_lower = message.lower()
        triggered_rules = []
        keywords = []
        score = 0.0
        
        # Brand detection
        for category, patterns in self.BRANDS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    triggered_rules.append(f'brand_impersonation_{category}')
                    score += 0.15
                    match = re.search(pattern, text_lower)
                    if match:
                        keywords.append(match.group())
        
        # Urgency detection
        urgency_count = 0
        for pattern in self.URGENCY_KEYWORDS:
            matches = list(re.finditer(pattern, text_lower))
            urgency_count += len(matches)
            for match in matches:
                keywords.append(match.group())
        
        if urgency_count > 0:
            triggered_rules.append('urgency_language')
            score += min(urgency_count * 0.1, 0.25)
        
        # Sensitive data
        for pattern in self.SENSITIVE_DATA:
            if re.search(pattern, text_lower):
                triggered_rules.append('sensitive_data_request')
                score += 0.25
                match = re.search(pattern, text_lower)
                if match:
                    keywords.append(match.group())
                break
        
        # URL detection
        if re.search(r'bit\.ly|tinyurl', text_lower):
            triggered_rules.append('shortened_url')
            score += 0.25
            keywords.append('shortened_url')
        
        score = min(score, 1.0)
        
        return {
            'score': score,
            'triggered_rules': list(set(triggered_rules)),
            'keywords': list(set(keywords))
        }
    
    def get_rule_explanation(self, rule: str) -> str:
        """Get explanation for a rule"""
        return self.EXPLANATIONS.get(rule, '')
