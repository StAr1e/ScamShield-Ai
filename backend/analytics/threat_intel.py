from typing import Dict
from datetime import datetime

class ThreatIntelligence:
    """Generate threat intelligence reports"""
    
    def __init__(self, analytics_tracker):
        self.analytics = analytics_tracker
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat intelligence report"""
        stats_24h = self.analytics.get_statistics(hours=24)
        
        return {
            'report_generated': datetime.now().isoformat(),
            'executive_summary': {
                'total_scams_24h': stats_24h.get('detection_summary', {}).get('scam_count', 0),
                'scam_rate_24h': stats_24h.get('detection_summary', {}).get('scam_percentage', 0),
                'average_risk_score': stats_24h.get('average_risk_scores', {}).get('overall', 0)
            },
            'top_threats': stats_24h.get('top_scam_patterns', [])[:5],
            'emerging_threats': [],
            'most_impersonated_brands': stats_24h.get('brand_impersonation_stats', {}),
            'recommendations': self._generate_recommendations(stats_24h)
        }
    
    def _generate_recommendations(self, stats: Dict) -> list:
        """Generate actionable recommendations"""
        recommendations = []
        
        scam_rate = stats.get('detection_summary', {}).get('scam_percentage', 0)
        if scam_rate > 30:
            recommendations.append('⚠️ High scam activity - increase user awareness')
        
        return recommendations
