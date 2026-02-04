from typing import List, Dict, Tuple, Optional
import re
import numpy as np
from collections import Counter
from datetime import datetime
import hashlib


class AdvancedTextAnalyzer:
    """Enhanced text analysis with linguistic features"""
    
    @staticmethod
    def extract_linguistic_features(text: str) -> Dict:
        """Extract advanced linguistic features for better detection"""
        features = {}
        
        # 1. Character-level features
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / max(len(text), 1)
        features['punctuation_ratio'] = sum(1 for c in text if c in '!?.,;:') / max(len(text), 1)
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        
        # 2. Word-level features
        words = text.lower().split()
        features['word_count'] = len(words)
        features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
        features['unique_word_ratio'] = len(set(words)) / max(len(words), 1)
        
        # 3. Sentence-level features
        sentences = re.split(r'[.!?]+', text)
        features['sentence_count'] = len([s for s in sentences if s.strip()])
        features['avg_sentence_length'] = np.mean([len(s.split()) for s in sentences if s.strip()]) if sentences else 0
        
        # 4. Scam-specific patterns
        features['has_numbers_in_text'] = bool(re.search(r'\d+', text))
        features['has_currency'] = bool(re.search(r'[\$£€₹]\s*\d+|rs\.?\s*\d+|\d+\s*(?:rupees|dollars|pounds)', text, re.I))
        features['has_phone_number'] = bool(re.search(r'\b\d{10,}\b', text))
        features['has_percentage'] = bool(re.search(r'\d+\s*%', text))
        features['has_all_caps_words'] = bool(re.search(r'\b[A-Z]{4,}\b', text))
        
        # 5. Urgency indicators (advanced)
        urgency_words = ['urgent', 'immediately', 'now', 'today', 'asap', 'quick', 'hurry', 'expires', 'deadline']
        features['urgency_word_count'] = sum(1 for word in urgency_words if word in text.lower())
        
        # 6. Emotional manipulation
        emotion_words = ['congratulations', 'winner', 'lucky', 'free', 'prize', 'claim', 'limited', 'exclusive']
        features['emotion_word_count'] = sum(1 for word in emotion_words if word in text.lower())
        
        # 7. Action verbs (imperative commands)
        action_verbs = ['click', 'call', 'send', 'reply', 'verify', 'confirm', 'update', 'download', 'install']
        features['action_verb_count'] = sum(1 for verb in action_verbs if verb in text.lower())
        
        return features
    
    @staticmethod
    def analyze_url_features(urls: List[str]) -> Dict:
        """Deep URL analysis"""
        if not urls:
            return {
                'url_count': 0,
                'has_suspicious_tld': False,
                'has_ip_address': False,
                'has_shortened_url': False,
                'avg_url_length': 0,
                'has_https': False,
                'subdomain_count': 0
            }
        
        features = {}
        features['url_count'] = len(urls)
        
        # TLD analysis
        suspicious_tlds = ['.xyz', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.club']
        features['has_suspicious_tld'] = any(any(tld in url.lower() for tld in suspicious_tlds) for url in urls)
        
        # IP address check
        features['has_ip_address'] = any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) for url in urls)
        
        # Shortened URL check
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'adf.ly']
        features['has_shortened_url'] = any(any(short in url.lower() for short in shorteners) for url in urls)
        
        # URL length (long URLs can be suspicious)
        features['avg_url_length'] = np.mean([len(url) for url in urls])
        
        # HTTPS check
        features['has_https'] = any(url.startswith('https://') for url in urls)
        
        # Subdomain analysis (many subdomains = suspicious)
        features['subdomain_count'] = np.mean([url.count('.') for url in urls])
        
        # Suspicious keywords in domain
        suspicious_keywords = ['secure', 'verify', 'update', 'login', 'account', 'bank', 'payment']
        features['has_suspicious_keyword'] = any(
            any(keyword in url.lower() for keyword in suspicious_keywords) 
            for url in urls
        )
        
        return features


class MultiLanguageDetector:
    """Enhanced language detection and translation"""
    
    # Urdu Unicode ranges
    URDU_RANGE = (0x0600, 0x06FF)
    
    # Roman Urdu common words with English translations
    ROMAN_URDU_DICT = {
        # Urgency
        'foran': 'immediately',
        'abhi': 'now',
        'turant': 'quickly',
        'jaldi': 'hurry',
        'jald': 'soon',
        
        # Actions
        'bhejo': 'send',
        'karo': 'do',
        'dekho': 'look',
        'click': 'click',
        
        # Finance
        'paisa': 'money',
        'rupay': 'rupees',
        'account': 'account',
        'bank': 'bank',
        
        # Common words
        'aap': 'you',
        'apka': 'your',
        'hai': 'is',
        'hain': 'are',
        'mein': 'in',
        'ko': 'to',
        'ka': 'of',
        'ki': 'of',
        'se': 'from',
        'ne': 'has',
        
        # Scam-specific
        'account band': 'account suspended',
        'otp bhejo': 'send otp',
        'verify karo': 'verify',
        'jeet gaye': 'you won',
        'inaam': 'prize'
    }
    
    @staticmethod
    def detect_language_advanced(text: str) -> Dict:
        """Advanced language detection with confidence scores"""
        # Count Urdu script characters
        urdu_chars = sum(1 for char in text if MultiLanguageDetector.URDU_RANGE[0] <= ord(char) <= MultiLanguageDetector.URDU_RANGE[1])
        
        # Count Roman Urdu words
        text_lower = text.lower()
        roman_urdu_words = sum(1 for word in MultiLanguageDetector.ROMAN_URDU_DICT.keys() if word in text_lower)
        
        # Count English words (simple heuristic)
        english_words = len(re.findall(r'\b[a-zA-Z]{3,}\b', text))
        
        total_chars = len(text)
        
        # Calculate confidence scores
        urdu_confidence = urdu_chars / max(total_chars, 1)
        roman_urdu_confidence = roman_urdu_words / max(len(text.split()), 1)
        english_confidence = english_words / max(len(text.split()), 1)
        
        # Determine primary language
        if urdu_confidence > 0.3:
            primary_language = 'urdu'
            confidence = urdu_confidence
        elif roman_urdu_confidence > 0.2:
            primary_language = 'roman_urdu'
            confidence = roman_urdu_confidence
        else:
            primary_language = 'english'
            confidence = english_confidence
        
        return {
            'primary_language': primary_language,
            'confidence': confidence,
            'urdu_score': urdu_confidence,
            'roman_urdu_score': roman_urdu_confidence,
            'english_score': english_confidence,
            'is_multilingual': (urdu_confidence > 0.1 and english_confidence > 0.1) or 
                              (roman_urdu_confidence > 0.1 and english_confidence > 0.1)
        }
    
    @staticmethod
    def translate_roman_urdu(text: str) -> str:
        """Translate Roman Urdu to English for better ML processing"""
        translated = text.lower()
        
        # Replace Roman Urdu words with English equivalents
        for urdu, english in MultiLanguageDetector.ROMAN_URDU_DICT.items():
            translated = re.sub(r'\b' + urdu + r'\b', english, translated)
        
        return translated


class BehavioralPatternAnalyzer:
    """Analyze behavioral patterns and anomalies"""
    
    @staticmethod
    def analyze_message_structure(text: str) -> Dict:
        """Analyze structural anomalies"""
        features = {}
        
        # 1. Spacing anomalies (excessive spaces can indicate spam)
        features['has_excessive_spaces'] = bool(re.search(r'\s{3,}', text))
        
        # 2. Repetitive characters (e.g., "URGENT!!!!!!!")
        features['has_char_repetition'] = bool(re.search(r'(.)\1{3,}', text))
        
        # 3. Mixed language (code-switching can be legitimate or suspicious)
        lang_info = MultiLanguageDetector.detect_language_advanced(text)
        features['is_code_switched'] = lang_info['is_multilingual']
        
        # 4. Unusual capitalization patterns
        words = text.split()
        if words:
            caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
            features['caps_word_ratio'] = caps_words / len(words)
        else:
            features['caps_word_ratio'] = 0
        
        # 5. Number density (many numbers = suspicious)
        features['number_density'] = len(re.findall(r'\d', text)) / max(len(text), 1)
        
        # 6. Special character abuse
        special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', text))
        features['special_char_ratio'] = special_chars / max(len(text), 1)
        
        return features
    
    @staticmethod
    def check_known_scam_templates(text: str) -> Dict:
        """Check against known scam message templates"""
        text_lower = text.lower()
        
        # Define scam templates (simplified fingerprints)
        templates = {
            'account_suspension': r'account.{0,20}(?:suspend|block|freeze|lock)',
            'prize_winning': r'(?:congratulation|winner).{0,30}(?:prize|won|claim)',
            'otp_request': r'(?:otp|code|pin).{0,20}(?:verify|confirm|enter|send)',
            'urgent_action': r'urgent.{0,30}(?:action|click|verify|update)',
            'payment_failure': r'payment.{0,20}(?:fail|decline|issue|problem)',
            'tax_refund': r'(?:tax|refund).{0,30}(?:claim|receive|pending)',
            'package_delivery': r'(?:package|parcel|delivery).{0,30}(?:fee|charge|pending)',
            'account_verification': r'(?:verify|confirm).{0,30}(?:account|identity|detail)'
        }
        
        matched_templates = []
        for template_name, pattern in templates.items():
            if re.search(pattern, text_lower):
                matched_templates.append(template_name)
        
        return {
            'matched_templates': matched_templates,
            'template_count': len(matched_templates),
            'is_template_match': len(matched_templates) > 0
        }


class EnhancedMLDetector:
    """Enhanced ML detector with advanced features"""
    
    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        
        # TF-IDF for text features
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 3),
            min_df=1,
            max_df=0.9,
            analyzer='word'
        )
        
        # Random Forest for better accuracy
        self.text_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            random_state=42,
            class_weight='balanced'
        )
        
        # Scaler for numerical features
        self.scaler = StandardScaler()
        
        # Feature analyzer
        self.text_analyzer = AdvancedTextAnalyzer()
        self.behavior_analyzer = BehavioralPatternAnalyzer()
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize with enhanced training data"""
        # Expanded training corpus
        scam_samples = [
            # Pakistan-specific scams
            "urgent your easypaisa account will be suspended verify kyc now",
            "jazzcash wallet blocked update cnic details immediately",
            "hbl account security alert verify credentials or account closed",
            "congratulations you won 500000 in telenor lucky draw claim now",
            "fbr tax refund pending claim with bank details",
            "nadra cnic update required verify within 24 hours",
            
            # Generic financial scams
            "your paypal account has been limited verify now to restore access",
            "unauthorized transaction detected on your card click to dispute",
            "bank account will be frozen verify identity immediately",
            "congratulations winner of 1000000 prize click claim reward",
            "security alert suspicious activity detected verify account asap",
            
            # OTP/Credential phishing
            "enter your otp to verify the transaction immediately",
            "confirm your password to prevent account suspension",
            "share your cvv and pin to complete verification",
            
            # URL-based scams
            "verify account now click bit.ly urgent action required",
            "update payment method here tinyurl immediate action needed",
            
            # Delivery scams
            "your package delivery pending pay fee to receive",
            "parcel held at customs pay clearance charges now",
            
            # Investment scams
            "guaranteed 300 percent returns invest now limited slots",
            "double your money in 30 days risk free investment",
            
            # Romance/Social scams
            "hello dear i need your help send money urgent",
            "stranded in foreign country need money for ticket",
            
            # Tech support scams
            "microsoft security alert virus detected call now",
            "google account compromised verify immediately",
            
            # Prize/Lottery scams
            "you won lottery claim prize send processing fee",
            "selected as lucky winner provide bank account details",
            
            # Roman Urdu scams
            "aap ka account band ho jayega foran verify karo",
            "aap jeet gaye hain inaam claim karo abhi",
            "otp bhejo urgent account update karna hai",
        ]
        
        safe_samples = [
            # Legitimate transactions
            "your order 12345 has been shipped track at amazon.com",
            "payment received thank you for your purchase",
            "transaction successful your balance is 5000 rupees",
            
            # Appointment reminders
            "reminder your appointment is tomorrow at 3pm",
            "meeting scheduled for next week please confirm attendance",
            
            # Subscriptions
            "your netflix subscription renews on 15th",
            "monthly statement is now available on our website",
            
            # Legitimate notifications
            "your easypaisa to 03001234567 of rs 500 successful",
            "jazzcash payment of rs 1000 sent successfully",
            
            # Marketing (legitimate)
            "special weekend offer 20 percent discount on all items",
            "new collection available visit our store this weekend",
            
            # Service updates
            "system maintenance scheduled for tonight no service interruption expected",
            "app update available download from play store",
            
            # Personal messages
            "hi how are you lets meet for coffee tomorrow",
            "can you pick up groceries on your way home",
            "happy birthday have a wonderful day ahead",
            
            # Work messages
            "please submit the report by friday end of day",
            "team meeting moved to conference room b",
        ]
        
        # Combine and create labels
        X_text = scam_samples + safe_samples
        y = [1] * len(scam_samples) + [0] * len(safe_samples)
        
        # Train TF-IDF and text model
        X_tfidf = self.tfidf_vectorizer.fit_transform(X_text)
        self.text_model.fit(X_tfidf, y)
    
    def extract_all_features(self, text: str, urls: List[str]) -> np.ndarray:
        """Extract comprehensive feature set"""
        # 1. Linguistic features
        ling_features = self.text_analyzer.extract_linguistic_features(text)
        
        # 2. URL features
        url_features = self.text_analyzer.analyze_url_features(urls)
        
        # 3. Behavioral features
        behavior_features = self.behavior_analyzer.analyze_message_structure(text)
        
        # 4. Template matching
        template_features = self.behavior_analyzer.check_known_scam_templates(text)
        
        # Combine all numerical features
        feature_vector = []
        
        # Add linguistic features
        feature_vector.extend([
            ling_features['uppercase_ratio'],
            ling_features['digit_ratio'],
            ling_features['punctuation_ratio'],
            ling_features['exclamation_count'],
            ling_features['question_count'],
            ling_features['word_count'],
            ling_features['avg_word_length'],
            ling_features['unique_word_ratio'],
            ling_features['urgency_word_count'],
            ling_features['emotion_word_count'],
            ling_features['action_verb_count'],
            1 if ling_features['has_numbers_in_text'] else 0,
            1 if ling_features['has_currency'] else 0,
            1 if ling_features['has_phone_number'] else 0,
        ])
        
        # Add URL features
        feature_vector.extend([
            url_features['url_count'],
            1 if url_features['has_suspicious_tld'] else 0,
            1 if url_features['has_ip_address'] else 0,
            1 if url_features['has_shortened_url'] else 0,
            url_features['avg_url_length'],
            1 if url_features['has_https'] else 0,
        ])
        
        # Add behavioral features
        feature_vector.extend([
            1 if behavior_features['has_excessive_spaces'] else 0,
            1 if behavior_features['has_char_repetition'] else 0,
            behavior_features['caps_word_ratio'],
            behavior_features['number_density'],
        ])
        
        # Add template features
        feature_vector.append(template_features['template_count'])
        
        return np.array(feature_vector)
    
    def predict_advanced(self, text: str, urls: List[str]) -> Dict:
        """Advanced prediction with multiple signals"""
        # Get TF-IDF probability
        X_tfidf = self.tfidf_vectorizer.transform([text])
        tfidf_prob = self.text_model.predict_proba(X_tfidf)[0][1]
        
        # Get feature-based score
        features = self.extract_all_features(text, urls)
        
        # Calculate feature-based risk score
        # High urgency words = high risk
        urgency_score = min(features[8] * 0.15, 0.3)  # urgency_word_count
        
        # High emotion words = medium risk
        emotion_score = min(features[9] * 0.1, 0.2)  # emotion_word_count
        
        # High action verbs = medium risk
        action_score = min(features[10] * 0.12, 0.25)  # action_verb_count
        
        # URL risks
        url_risk = 0
        if features[16]:  # has_suspicious_tld
            url_risk += 0.2
        if features[18]:  # has_shortened_url
            url_risk += 0.25
        if features[17]:  # has_ip_address
            url_risk += 0.2
        
        # Template matching risk
        template_risk = min(features[-1] * 0.15, 0.3)  # template_count
        
        # Combine all signals
        feature_based_score = urgency_score + emotion_score + action_score + url_risk + template_risk
        feature_based_score = min(feature_based_score, 1.0)
        
        # Weighted combination: TF-IDF (70%) + Features (30%)
        final_ml_probability = (tfidf_prob * 0.7) + (feature_based_score * 0.3)
        
        return {
            'ml_probability': final_ml_probability,
            'tfidf_score': tfidf_prob,
            'feature_score': feature_based_score,
            'confidence': abs(final_ml_probability - 0.5) * 2,  # How confident (0-1)
            'feature_breakdown': {
                'urgency_risk': urgency_score,
                'emotion_risk': emotion_score,
                'action_risk': action_score,
                'url_risk': url_risk,
                'template_risk': template_risk
            }
        }
