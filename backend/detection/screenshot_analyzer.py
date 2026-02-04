import re
from typing import Dict, List, Optional
from datetime import datetime
import hashlib


class FakeScreenshotDetector:
    """Detect fake payment screenshots and manipulated images"""
    
    # Known payment app UI patterns
    PAYMENT_APP_PATTERNS = {
        'easypaisa': {
            'header_text': ['easypaisa', 'telenor microfinance bank'],
            'transaction_fields': ['transaction id', 'to', 'from', 'amount', 'date'],
            'id_format': r'EP\d{10,}',
            'colors': ['#E31E24', '#FFFFFF'],  # Red and white
        },
        'jazzcash': {
            'header_text': ['jazzcash', 'mobilink microfinance bank'],
            'transaction_fields': ['transaction id', 'txn id', 'amount', 'date', 'time'],
            'id_format': r'JC\d{10,}',
            'colors': ['#FF6B00', '#FFFFFF'],  # Orange and white
        },
        'hbl': {
            'header_text': ['hbl', 'habib bank limited'],
            'transaction_fields': ['reference', 'amount', 'account', 'date'],
            'id_format': r'HBL\d{8,}',
            'colors': ['#00A651', '#FFFFFF'],  # Green and white
        }
    }
    
    @staticmethod
    def analyze_text_from_image(extracted_text: str) -> Dict:
        """
        Analyze OCR extracted text from screenshot
        
        Args:
            extracted_text: Text extracted from image using OCR
            
        Returns:
            Analysis results with fraud indicators
        """
        text_lower = extracted_text.lower()
        
        results = {
            'is_payment_screenshot': False,
            'detected_app': None,
            'fraud_indicators': [],
            'risk_score': 0.0,
            'confidence': 0.0
        }
        
        # Detect which payment app
        for app_name, patterns in FakeScreenshotDetector.PAYMENT_APP_PATTERNS.items():
            if any(header in text_lower for header in patterns['header_text']):
                results['is_payment_screenshot'] = True
                results['detected_app'] = app_name
                break
        
        if not results['is_payment_screenshot']:
            return results
        
        app_patterns = FakeScreenshotDetector.PAYMENT_APP_PATTERNS[results['detected_app']]
        
        # Check 1: Transaction ID format
        transaction_id = re.search(app_patterns['id_format'], extracted_text)
        if not transaction_id:
            results['fraud_indicators'].append('Invalid or missing transaction ID format')
            results['risk_score'] += 0.3
        
        # Check 2: Required fields present
        missing_fields = []
        for field in app_patterns['transaction_fields']:
            if field not in text_lower:
                missing_fields.append(field)
        
        if missing_fields:
            results['fraud_indicators'].append(f'Missing fields: {", ".join(missing_fields)}')
            results['risk_score'] += 0.2
        
        # Check 3: Detect "Inspect Element" artifacts
        inspect_keywords = ['inspect element', 'developer tools', 'console', 'devtools']
        if any(keyword in text_lower for keyword in inspect_keywords):
            results['fraud_indicators'].append('Browser developer tools detected (Inspect Element)')
            results['risk_score'] += 0.9  # Almost certainly fake
        
        # Check 4: Unrealistic amounts
        amounts = re.findall(r'(?:rs\.?|pkr)\s*([0-9,]+)', text_lower)
        if amounts:
            amount_str = amounts[0].replace(',', '')
            try:
                amount = float(amount_str)
                if amount > 1000000:  # More than 10 lakh
                    results['fraud_indicators'].append('Suspiciously high transaction amount')
                    results['risk_score'] += 0.2
                elif amount % 1000 == 0 and amount > 10000:  # Round thousands
                    results['fraud_indicators'].append('Suspiciously round amount (possible manipulation)')
                    results['risk_score'] += 0.1
            except ValueError:
                pass
        
        # Check 5: Date/Time inconsistencies
        dates = re.findall(r'\d{1,2}[-/]\d{1,2}[-/]\d{2,4}', extracted_text)
        times = re.findall(r'\d{1,2}:\d{2}', extracted_text)
        
        if dates:
            # Check if date is in the future
            try:
                date_str = dates[0]
                # Simple validation (can be enhanced)
                if '2099' in date_str or '2050' in date_str:
                    results['fraud_indicators'].append('Future date detected')
                    results['risk_score'] += 0.4
            except:
                pass
        
        # Check 6: Screenshot quality indicators
        if 'screenshot' in text_lower or 'screen capture' in text_lower:
            results['fraud_indicators'].append('Screenshot watermark detected')
            results['risk_score'] += 0.15
        
        # Check 7: Multiple currency symbols
        currency_count = len(re.findall(r'[\$£€₹]', extracted_text))
        if currency_count > 1:
            results['fraud_indicators'].append('Multiple currency symbols (unusual)')
            results['risk_score'] += 0.2
        
        # Check 8: Duplicate transaction IDs (if checking history)
        # This would require a database lookup in production
        
        # Calculate final risk score
        results['risk_score'] = min(results['risk_score'], 1.0)
        results['confidence'] = 0.8 if results['fraud_indicators'] else 0.5
        
        return results
    
    @staticmethod
    def check_image_metadata(image_path: str) -> Dict:
        """
        Check image metadata for manipulation signs
        (Requires PIL/Pillow in production)
        
        Returns metadata analysis
        """
        # This is a placeholder for actual implementation
        # In production, use PIL.Image to extract EXIF data
        
        metadata_checks = {
            'has_exif_data': False,
            'modification_detected': False,
            'creation_date': None,
            'software_used': None,
            'warnings': []
        }
        
        # Placeholder logic
        # Real implementation would:
        # 1. Check EXIF data for editor software (Photoshop, GIMP, etc.)
        # 2. Verify creation/modification dates
        # 3. Check for multiple save operations
        # 4. Detect compression artifacts
        
        return metadata_checks
    
    @staticmethod
    def verify_transaction_id(transaction_id: str, app_name: str) -> Dict:
        """
        Verify transaction ID format and checksum
        
        Args:
            transaction_id: The transaction ID to verify
            app_name: Payment app name (easypaisa, jazzcash, etc.)
            
        Returns:
            Verification results
        """
        results = {
            'is_valid_format': False,
            'checksum_valid': False,
            'warnings': []
        }
        
        if app_name not in FakeScreenshotDetector.PAYMENT_APP_PATTERNS:
            results['warnings'].append('Unknown payment app')
            return results
        
        pattern = FakeScreenshotDetector.PAYMENT_APP_PATTERNS[app_name]['id_format']
        
        # Check format
        if re.match(pattern, transaction_id):
            results['is_valid_format'] = True
        else:
            results['warnings'].append('Invalid transaction ID format')
        
        # Check length (most Pakistani payment IDs are 12-15 digits)
        if len(transaction_id) < 10 or len(transaction_id) > 20:
            results['warnings'].append('Unusual transaction ID length')
        
        # Simple checksum validation (placeholder)
        # Real implementation would use actual checksum algorithms
        digits = re.findall(r'\d', transaction_id)
        if digits:
            checksum = sum(int(d) for d in digits) % 10
            # This is a simplified check; real apps use complex algorithms
            results['checksum_valid'] = checksum != 0
        
        return results
    
    @staticmethod
    def generate_screenshot_report(extracted_text: str, image_path: Optional[str] = None) -> Dict:
        """
        Generate comprehensive screenshot analysis report
        
        Args:
            extracted_text: OCR extracted text
            image_path: Path to image file (optional)
            
        Returns:
            Complete analysis report
        """
        # Analyze text content
        text_analysis = FakeScreenshotDetector.analyze_text_from_image(extracted_text)
        
        # Analyze metadata (if image provided)
        metadata_analysis = {}
        if image_path:
            metadata_analysis = FakeScreenshotDetector.check_image_metadata(image_path)
        
        # Combine analyses
        combined_risk = text_analysis['risk_score']
        
        # Increase risk if metadata shows manipulation
        if metadata_analysis.get('modification_detected'):
            combined_risk += 0.3
        if metadata_analysis.get('software_used') in ['photoshop', 'gimp', 'paint.net']:
            combined_risk += 0.2
        
        combined_risk = min(combined_risk, 1.0)
        
        # Classify
        if combined_risk >= 0.7:
            classification = 'FAKE'
        elif combined_risk >= 0.4:
            classification = 'SUSPICIOUS'
        else:
            classification = 'AUTHENTIC'
        
        report = {
            'classification': classification,
            'risk_score': round(combined_risk * 100, 2),
            'detected_app': text_analysis.get('detected_app'),
            'is_payment_screenshot': text_analysis.get('is_payment_screenshot'),
            'fraud_indicators': text_analysis.get('fraud_indicators', []),
            'metadata_warnings': metadata_analysis.get('warnings', []),
            'recommendations': FakeScreenshotDetector._generate_recommendations(classification, text_analysis),
            'analyzed_at': datetime.now().isoformat()
        }
        
        return report
    
    @staticmethod
    def _generate_recommendations(classification: str, analysis: Dict) -> List[str]:
        """Generate recommendations based on classification"""
        recommendations = []
        
        if classification == 'FAKE':
            recommendations.extend([
                '🚫 DO NOT trust this screenshot - high probability of manipulation',
                '📞 Verify directly with the payment app or bank',
                '🚨 Report to authorities if used in fraud attempt',
                '🔍 Request official transaction confirmation from app'
            ])
        elif classification == 'SUSPICIOUS':
            recommendations.extend([
                '⚠️ Verify this transaction through official channels',
                '📱 Check your payment app transaction history',
                '🔍 Look for the transaction ID in your app',
                '📞 Contact customer support if suspicious'
            ])
        else:
            recommendations.extend([
                '✅ Screenshot appears authentic',
                '🔍 Still verify important transactions through official app',
                '📱 Cross-check transaction ID in your payment history'
            ])
        
        # Add specific recommendations based on indicators
        if 'Inspect Element' in str(analysis.get('fraud_indicators', [])):
            recommendations.append('🖥️ This screenshot shows browser developer tools - likely fake')
        
        if 'Invalid or missing transaction ID' in str(analysis.get('fraud_indicators', [])):
            recommendations.append('🆔 Transaction ID format is incorrect for this app')
        
        return recommendations


class ScreenshotTextExtractor:
    """
    Wrapper for OCR text extraction
    In production, use pytesseract or cloud OCR services
    """
    
    @staticmethod
    def extract_text(image_path: str) -> str:
        """
        Extract text from image using OCR
        
        This is a placeholder. In production, use:
        - pytesseract (local OCR)
        - Google Cloud Vision API
        - AWS Textract
        - Azure Computer Vision
        
        Args:
            image_path: Path to image file
            
        Returns:
            Extracted text
        """
        # Placeholder implementation
        # Real code would be:
        # from PIL import Image
        # import pytesseract
        # image = Image.open(image_path)
        # text = pytesseract.image_to_string(image)
        # return text
        
        return """
        This is a placeholder for OCR extracted text.
        In production, this would contain the actual text from the image.
        """
    
    @staticmethod
    def preprocess_image(image_path: str) -> str:
        """
        Preprocess image for better OCR results
        - Convert to grayscale
        - Increase contrast
        - Remove noise
        - Deskew if needed
        
        Returns path to preprocessed image
        """
        # Placeholder for image preprocessing
        # Real implementation would use OpenCV or PIL
        return image_path


# Example usage function
def analyze_payment_screenshot(image_path: str) -> Dict:
    """
    Main function to analyze a payment screenshot
    
    Args:
        image_path: Path to screenshot image
        
    Returns:
        Complete analysis report
    """
    # Step 1: Extract text from image
    extracted_text = ScreenshotTextExtractor.extract_text(image_path)
    
    # Step 2: Analyze the screenshot
    report = FakeScreenshotDetector.generate_screenshot_report(extracted_text, image_path)
    
    return report
