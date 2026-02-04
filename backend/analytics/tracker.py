from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import json
import hashlib


class ScamAnalytics:
    """Track and analyze scam patterns over time"""
    
    def __init__(self):
        # In-memory storage (use database in production)
        self.detections = []
        self.scam_patterns = defaultdict(int)
        self.brand_mentions = Counter()
        self.url_patterns = Counter()
        self.language_distribution = Counter()
        
    def log_detection(self, analysis_result: Dict, message: str):
        """
        Log a detection for analytics
        
        Args:
            analysis_result: Result from scam analysis
            message: Original message (anonymized)
        """
        # Anonymize message (remove PII)
        anonymized_message = self._anonymize_message(message)
        
        detection_record = {
            'timestamp': datetime.now().isoformat(),
            'classification': analysis_result.get('classification'),
            'risk_score': analysis_result.get('risk_score'),
            'ml_probability': analysis_result.get('ml_probability'),
            'rule_score': analysis_result.get('rule_score'),
            'triggered_rules': analysis_result.get('triggered_rules', []),
            'language': analysis_result.get('language_detected'),
            'message_hash': hashlib.sha256(message.encode()).hexdigest()[:16],
            'message_length': len(message),
            'has_urls': len(analysis_result.get('highlighted_keywords', [])) > 0
        }
        
        # Store detection
        self.detections.append(detection_record)
        
        # Update counters
        self._update_counters(detection_record, analysis_result)
        
        # Keep only last 10,000 detections in memory
        if len(self.detections) > 10000:
            self.detections = self.detections[-10000:]
    
    def _anonymize_message(self, message: str) -> str:
        """Remove PII from message for storage"""
        import re
        
        # Remove phone numbers
        message = re.sub(r'\b\d{10,}\b', '[PHONE]', message)
        
        # Remove CNICs (Pakistani ID format: XXXXX-XXXXXXX-X)
        message = re.sub(r'\b\d{5}-\d{7}-\d{1}\b', '[CNIC]', message)
        
        # Remove email addresses
        message = re.sub(r'\b[\w.-]+@[\w.-]+\.\w+\b', '[EMAIL]', message)
        
        # Remove card numbers (simple pattern)
        message = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD]', message)
        
        # Remove specific URLs (keep domain only)
        message = re.sub(r'https?://[^\s]+', '[URL]', message)
        
        return message
    
    def _update_counters(self, record: Dict, analysis: Dict):
        """Update analytics counters"""
        # Count triggered rules
        for rule in record.get('triggered_rules', []):
            self.scam_patterns[rule] += 1
        
        # Count language distribution
        if record.get('language'):
            self.language_distribution[record['language']] += 1
        
        # Extract brands from triggered rules
        for rule in record.get('triggered_rules', []):
            if 'brand_impersonation' in rule:
                brand = rule.replace('brand_impersonation_', '')
                self.brand_mentions[brand] += 1
    
    def get_statistics(self, hours: int = 24) -> Dict:
        """
        Get analytics for the specified time period
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Statistics dictionary
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter recent detections
        recent = [
            d for d in self.detections 
            if datetime.fromisoformat(d['timestamp']) > cutoff_time
        ]
        
        if not recent:
            return self._get_empty_stats()
        
        # Calculate statistics
        total_analyzed = len(recent)
        scams = [d for d in recent if d['classification'] == 'SCAM']
        suspicious = [d for d in recent if d['classification'] == 'SUSPICIOUS']
        safe = [d for d in recent if d['classification'] == 'SAFE']
        
        stats = {
            'time_period_hours': hours,
            'total_messages_analyzed': total_analyzed,
            'detection_summary': {
                'scam_count': len(scams),
                'suspicious_count': len(suspicious),
                'safe_count': len(safe),
                'scam_percentage': round(len(scams) / total_analyzed * 100, 2) if total_analyzed > 0 else 0
            },
            'average_risk_scores': {
                'overall': round(sum(d['risk_score'] for d in recent) / total_analyzed, 2) if total_analyzed > 0 else 0,
                'scams_only': round(sum(d['risk_score'] for d in scams) / len(scams), 2) if scams else 0
            },
            'top_scam_patterns': self._get_top_patterns(recent, limit=10),
            'brand_impersonation_stats': self._get_brand_stats(recent),
            'language_distribution': dict(Counter(d['language'] for d in recent if d.get('language'))),
            'trend_analysis': self._analyze_trends(recent),
            'generated_at': datetime.now().isoformat()
        }
        
        return stats
    
    def _get_empty_stats(self) -> Dict:
        """Return empty statistics structure"""
        return {
            'time_period_hours': 0,
            'total_messages_analyzed': 0,
            'detection_summary': {
                'scam_count': 0,
                'suspicious_count': 0,
                'safe_count': 0,
                'scam_percentage': 0
            },
            'message': 'No data available for the specified time period'
        }
    
    def _get_top_patterns(self, detections: List[Dict], limit: int = 10) -> List[Dict]:
        """Get most common scam patterns"""
        pattern_counts = Counter()
        
        for detection in detections:
            if detection['classification'] in ['SCAM', 'SUSPICIOUS']:
                for rule in detection.get('triggered_rules', []):
                    pattern_counts[rule] += 1
        
        top_patterns = []
        for pattern, count in pattern_counts.most_common(limit):
            top_patterns.append({
                'pattern': pattern,
                'count': count,
                'description': self._get_pattern_description(pattern)
            })
        
        return top_patterns
    
    def _get_pattern_description(self, pattern: str) -> str:
        """Get human-readable pattern description"""
        descriptions = {
            'brand_impersonation_pakistan_financial': 'Easypaisa/JazzCash impersonation',
            'brand_impersonation_global_financial': 'PayPal/Stripe impersonation',
            'brand_impersonation_global_tech': 'WhatsApp/Google impersonation',
            'brand_impersonation_government': 'FBR/NADRA impersonation',
            'urgency_language': 'Urgent action required tactics',
            'suspicious_actions': 'Multiple action requests (click, verify)',
            'sensitive_data_request': 'Requests for OTP, PIN, passwords',
            'threat_language': 'Account suspension threats',
            'financial_manipulation': 'Prize/reward promises',
            'shortened_url': 'Shortened URL links (bit.ly, etc.)',
            'suspicious_domain_extension': 'Suspicious domains (.xyz, .tk)',
            'suspicious_domain_pattern': 'Phishing domain patterns'
        }
        return descriptions.get(pattern, pattern.replace('_', ' ').title())
    
    def _get_brand_stats(self, detections: List[Dict]) -> Dict:
        """Get brand impersonation statistics"""
        brand_counts = Counter()
        
        for detection in detections:
            for rule in detection.get('triggered_rules', []):
                if 'brand_impersonation' in rule:
                    brand = rule.replace('brand_impersonation_', '')
                    brand_counts[brand] += 1
        
        return dict(brand_counts.most_common(10))
    
    def _analyze_trends(self, detections: List[Dict]) -> Dict:
        """Analyze trends over time"""
        # Group by hour
        hourly_counts = defaultdict(lambda: {'scam': 0, 'suspicious': 0, 'safe': 0})
        
        for detection in detections:
            timestamp = datetime.fromisoformat(detection['timestamp'])
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
            
            classification = detection['classification'].lower()
            hourly_counts[hour_key][classification] += 1
        
        # Calculate trend (increasing or decreasing)
        hours = sorted(hourly_counts.keys())
        if len(hours) >= 2:
            first_half_scams = sum(hourly_counts[h]['scam'] for h in hours[:len(hours)//2])
            second_half_scams = sum(hourly_counts[h]['scam'] for h in hours[len(hours)//2:])
            
            if second_half_scams > first_half_scams * 1.2:
                trend = 'increasing'
            elif second_half_scams < first_half_scams * 0.8:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
        
        return {
            'trend': trend,
            'hourly_breakdown': dict(hourly_counts)
        }
    
    def get_emerging_threats(self) -> List[Dict]:
        """Identify new or emerging scam patterns"""
        # Get recent detections (last 24 hours)
        recent = self.get_statistics(hours=24)
        
        # Get older detections (24-48 hours ago)
        older = self.get_statistics(hours=48)
        
        emerging = []
        
        # Compare patterns
        recent_patterns = {p['pattern']: p['count'] for p in recent.get('top_scam_patterns', [])}
        older_patterns = {p['pattern']: p['count'] for p in older.get('top_scam_patterns', [])}
        
        for pattern, recent_count in recent_patterns.items():
            older_count = older_patterns.get(pattern, 0)
            
            # Pattern is emerging if it increased by >50% or is new
            if older_count == 0 or recent_count > older_count * 1.5:
                emerging.append({
                    'pattern': pattern,
                    'description': self._get_pattern_description(pattern),
                    'recent_count': recent_count,
                    'previous_count': older_count,
                    'change_percentage': round((recent_count - older_count) / max(older_count, 1) * 100, 2)
                })
        
        # Sort by change percentage
        emerging.sort(key=lambda x: x['change_percentage'], reverse=True)
        
        return emerging[:5]  # Top 5 emerging threats
    
    def get_threat_intelligence(self) -> Dict:
        """Generate threat intelligence report"""
        stats_24h = self.get_statistics(hours=24)
        stats_7d = self.get_statistics(hours=168)  # 7 days
        emerging = self.get_emerging_threats()
        
        intelligence = {
            'report_generated': datetime.now().isoformat(),
            'executive_summary': {
                'total_scams_24h': stats_24h['detection_summary']['scam_count'],
                'total_scams_7d': stats_7d['detection_summary']['scam_count'],
                'scam_rate_24h': stats_24h['detection_summary']['scam_percentage'],
                'average_risk_score': stats_24h['average_risk_scores']['overall']
            },
            'top_threats': stats_24h.get('top_scam_patterns', [])[:5],
            'emerging_threats': emerging,
            'most_impersonated_brands': stats_24h.get('brand_impersonation_stats', {}),
            'language_breakdown': stats_24h.get('language_distribution', {}),
            'trend': stats_24h['trend_analysis']['trend'] if 'trend_analysis' in stats_24h else 'unknown',
            'recommendations': self._generate_threat_recommendations(stats_24h, emerging)
        }
        
        return intelligence
    
    def _generate_threat_recommendations(self, stats: Dict, emerging: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on threat intelligence"""
        recommendations = []
        
        # High scam rate
        if stats['detection_summary']['scam_percentage'] > 30:
            recommendations.append('⚠️ High scam activity detected - increase user awareness campaigns')
        
        # Emerging threats
        if emerging:
            top_emerging = emerging[0]['pattern']
            recommendations.append(f'🆕 New threat pattern emerging: {self._get_pattern_description(top_emerging)}')
        
        # Brand impersonation
        if stats.get('brand_impersonation_stats'):
            top_brand = max(stats['brand_impersonation_stats'].items(), key=lambda x: x[1])[0]
            recommendations.append(f'🏦 Alert: High {top_brand} impersonation - warn users')
        
        # Language-specific
        lang_dist = stats.get('language_distribution', {})
        if 'urdu' in lang_dist or 'roman_urdu' in lang_dist:
            recommendations.append('🌐 Multi-language scams detected - ensure Urdu support')
        
        return recommendations


class ThreatIntelligenceFeed:
    """External threat intelligence integration"""
    
    @staticmethod
    def get_known_malicious_urls() -> List[str]:
        """
        Get list of known malicious URLs
        In production, integrate with:
        - Google Safe Browsing API
        - PhishTank
        - URLhaus
        - VirusTotal
        """
        # Placeholder - in production, fetch from threat feeds
        return [
            'bit.ly/scam123',
            'tinyurl.com/fraud456',
            'suspicious-bank.xyz',
            'verify-account.tk'
        ]
    
    @staticmethod
    def get_known_scam_phone_numbers() -> List[str]:
        """Get list of known scam phone numbers"""
        # Placeholder - integrate with spam databases
        return [
            '+92300xxxxxxx',  # Anonymized
            '+92321xxxxxxx'
        ]
    
    @staticmethod
    def report_new_threat(threat_data: Dict) -> bool:
        """
        Report new threat to external databases
        
        Args:
            threat_data: Information about the new threat
            
        Returns:
            Success status
        """
        # In production, submit to:
        # - PhishTank
        # - Spamhaus
        # - Local cybercrime authorities
        
        # Log for now
        print(f"New threat reported: {threat_data}")
        return True


class PerformanceMetrics:
    """Track model performance and accuracy"""
    
    def __init__(self):
        self.predictions = []
        self.user_feedback = []
    
    def log_prediction(self, message_hash: str, prediction: str, confidence: float):
        """Log a prediction for performance tracking"""
        self.predictions.append({
            'timestamp': datetime.now().isoformat(),
            'message_hash': message_hash,
            'prediction': prediction,
            'confidence': confidence
        })
    
    def log_user_feedback(self, message_hash: str, actual_label: str):
        """Log user feedback (was the prediction correct?)"""
        self.user_feedback.append({
            'timestamp': datetime.now().isoformat(),
            'message_hash': message_hash,
            'actual_label': actual_label
        })
    
    def calculate_accuracy(self) -> Dict:
        """Calculate model accuracy based on user feedback"""
        if not self.user_feedback:
            return {'accuracy': None, 'message': 'No feedback data available'}
        
        # Match predictions with feedback
        feedback_dict = {f['message_hash']: f['actual_label'] for f in self.user_feedback}
        
        correct = 0
        total = 0
        
        for pred in self.predictions:
            if pred['message_hash'] in feedback_dict:
                total += 1
                if pred['prediction'] == feedback_dict[pred['message_hash']]:
                    correct += 1
        
        if total == 0:
            return {'accuracy': None, 'message': 'No matched predictions'}
        
        accuracy = correct / total
        
        return {
            'accuracy': round(accuracy * 100, 2),
            'correct_predictions': correct,
            'total_evaluated': total,
            'sample_size': len(self.user_feedback)
        }


# Global analytics instance
analytics = ScamAnalytics()
performance_metrics = PerformanceMetrics()
