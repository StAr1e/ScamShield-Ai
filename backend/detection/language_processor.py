import re
from typing import Dict

class LanguageProcessor:
    """Process and detect message language"""
    
    def __init__(self):
        self.URDU_RANGE = (0x0600, 0x06FF)
        self.ROMAN_URDU_WORDS = ['aap', 'apka', 'hai', 'mein', 'ko', 'ka', 'foran', 'abhi']
    
    def process(self, message: str, language_hint: str = "auto") -> Dict:
        """Process message and detect language"""
        
        # Detect language
        if language_hint == "auto":
            lang, confidence = self._detect_language(message)
        else:
            lang = language_hint
            confidence = 1.0
        
        # Normalize text
        processed = message.lower().strip()
        processed = re.sub(r'\s+', ' ', processed)
        
        # Translate Roman Urdu if needed
        if lang == 'roman_urdu':
            processed = self._translate_roman_urdu(processed)
        
        return {
            'language': lang,
            'confidence': confidence,
            'processed_text': processed,
            'original_text': message
        }
    
    def _detect_language(self, text: str) -> tuple:
        """Detect language with confidence"""
        # Check Urdu script
        urdu_chars = sum(1 for c in text if self.URDU_RANGE[0] <= ord(c) <= self.URDU_RANGE[1])
        if urdu_chars > 5:
            return 'urdu', urdu_chars / max(len(text), 1)
        
        # Check Roman Urdu
        text_lower = text.lower()
        roman_count = sum(1 for word in self.ROMAN_URDU_WORDS if word in text_lower)
        if roman_count >= 2:
            return 'roman_urdu', roman_count / max(len(text.split()), 1)
        
        return 'english', 0.95
    
    def _translate_roman_urdu(self, text: str) -> str:
        """Translate common Roman Urdu words"""
        translations = {
            'foran': 'immediately',
            'abhi': 'now',
            'aap': 'you',
            'apka': 'your',
            'hai': 'is'
        }
        
        for urdu, english in translations.items():
            text = re.sub(r'\b' + urdu + r'\b', english, text)
        
        return text
