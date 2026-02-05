from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
import os

# Import detection engines
from detection.ml_detector import EnhancedMLDetector
from detection.rule_detector import RuleDetector
from detection.language_processor import LanguageProcessor
from detection.screenshot_analyzer import FakeScreenshotDetector

# Import analytics
from analytics.tracker import AnalyticsTracker
from analytics.threat_intel import ThreatIntelligence

# Import configuration
from core.config import settings
from core.logger import logger

# Initialize FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="AI-powered scam and fraud detection system"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class MessageRequest(BaseModel):
    message: str
    language: Optional[str] = "auto"


class AnalysisResponse(BaseModel):
    classification: str
    risk_score: float
    ml_score: float
    rule_score: float
    confidence: float
    explanation: List[str]
    highlighted_keywords: List[str]
    triggered_rules: List[str]
    safety_recommendations: List[str]
    language_info: Dict
    analyzed_at: str
    message_hash: str


class ScreenshotRequest(BaseModel):
    extracted_text: str


class ScreenshotResponse(BaseModel):
    classification: str
    risk_score: float
    detected_app: Optional[str]
    fraud_indicators: List[str]
    recommendations: List[str]
    analyzed_at: str


# ============================================================================
# INITIALIZE COMPONENTS (Singleton Pattern)
# ============================================================================

class DetectionEngine:
    """Singleton detection engine with all components"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DetectionEngine, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize all detection components"""
        logger.info("Initializing ScamShield AI Detection Engine...")
        
        # Language processing
        self.language_processor = LanguageProcessor()
        
        # ML detector (if enabled)
        if settings.ENABLE_ML:
            self.ml_detector = EnhancedMLDetector(
                model_type=settings.ML_MODEL_TYPE,
                model_path=settings.ML_MODEL_PATH
            )
        else:
            self.ml_detector = None
        
        # Rule-based detector
        self.rule_detector = RuleDetector(
            rules_path=settings.RULES_PATH
        )
        
        # Screenshot analyzer (if enabled)
        if settings.ENABLE_SCREENSHOT_DETECTION:
            self.screenshot_analyzer = FakeScreenshotDetector()
        else:
            self.screenshot_analyzer = None
        
        # Analytics tracker
        if settings.ENABLE_ANALYTICS:
            self.analytics = AnalyticsTracker()
            self.threat_intel = ThreatIntelligence(self.analytics)
        else:
            self.analytics = None
            self.threat_intel = None
        
        logger.info("Detection engine initialized successfully")
    
    def analyze_message(self, message: str, language: str = "auto") -> Dict:
        """
        Main analysis pipeline
        
        Args:
            message: Message text to analyze
            language: Language hint (auto/en/urdu/roman_urdu)
            
        Returns:
            Complete analysis results
        """
        # Step 1: Language processing
        lang_info = self.language_processor.process(message, language)
        processed_text = lang_info['processed_text']
        
        # Step 2: ML detection (if enabled)
        if self.ml_detector and settings.ENABLE_ML:
            ml_result = self.ml_detector.predict(processed_text)
            ml_score = ml_result['probability']
        else:
            ml_score = 0.0
        
        # Step 3: Rule-based detection
        rule_result = self.rule_detector.analyze(message, lang_info)
        rule_score = rule_result['score']
        
        # Step 4: Hybrid classification
        final_score = self._calculate_final_score(ml_score, rule_score)
        classification = self._classify(final_score)
        confidence = self._calculate_confidence(ml_score, rule_score)
        
        # Step 5: Generate explanations
        explanations = self._generate_explanations(
            classification, ml_score, rule_score, rule_result, lang_info
        )
        
        # Step 6: Generate recommendations
        recommendations = self._generate_recommendations(
            classification, rule_result['triggered_rules'], lang_info
        )
        
        # Step 7: Prepare response
        result = {
            'classification': classification,
            'risk_score': round(final_score * 100, 2),
            'ml_score': round(ml_score, 4),
            'rule_score': round(rule_score, 4),
            'confidence': round(confidence, 4),
            'explanation': explanations,
            'highlighted_keywords': rule_result['keywords'],
            'triggered_rules': rule_result['triggered_rules'],
            'safety_recommendations': recommendations,
            'language_info': {
                'detected': lang_info['language'],
                'confidence': round(lang_info['confidence'], 4)
            },
            'analyzed_at': datetime.now().isoformat(),
            'message_hash': self._generate_hash(message)
        }
        
        # Step 8: Log analytics (if enabled)
        if self.analytics:
            self.analytics.log_detection(result, message)
        
        return result
    
    def _calculate_final_score(self, ml_score: float, rule_score: float) -> float:
        """Combine ML and rule scores based on configuration"""
        ml_weight = settings.ML_WEIGHT
        rule_weight = settings.RULE_WEIGHT
        
        final = (ml_score * ml_weight) + (rule_score * rule_weight)
        return min(final, 1.0)
    
    def _classify(self, score: float) -> str:
        """Classify based on threshold configuration"""
        if score >= settings.SCAM_THRESHOLD:
            return "SCAM"
        elif score >= settings.SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        else:
            return "SAFE"
    
    def _calculate_confidence(self, ml_score: float, rule_score: float) -> float:
        """Calculate confidence based on ML and rule agreement"""
        if ml_score == 0:  # ML disabled
            return min(rule_score * 1.2, 1.0)
        
        agreement = 1 - abs(ml_score - rule_score)
        avg_score = (ml_score + rule_score) / 2
        confidence = avg_score * agreement * 1.5
        return min(confidence, 1.0)
    
    def _generate_explanations(self, classification: str, ml_score: float, 
                              rule_score: float, rule_result: Dict, 
                              lang_info: Dict) -> List[str]:
        """Generate human-readable explanations"""
        explanations = []
        
        # ML explanation
        if settings.ENABLE_ML and ml_score > 0:
            if ml_score > 0.75:
                explanations.append(
                    f"🤖 AI Detection: {ml_score*100:.1f}% scam probability - "
                    "Strong match with known scam patterns"
                )
            elif ml_score > 0.45:
                explanations.append(
                    f"🤖 AI Alert: {ml_score*100:.1f}% scam probability - "
                    "Suspicious language patterns detected"
                )
        
        # Language info
        if lang_info['language'] != 'english':
            explanations.append(
                f"🌐 Language: {lang_info['language'].upper()} detected "
                f"({lang_info['confidence']*100:.0f}% confidence)"
            )
        
        # Rule explanations
        for rule in rule_result['triggered_rules']:
            explanation = self.rule_detector.get_rule_explanation(rule)
            if explanation:
                explanations.append(explanation)
        
        # Multi-flag warning
        if len(rule_result['triggered_rules']) >= 3:
            explanations.append(
                "🔴 Multiple Red Flags: Several scam indicators detected simultaneously"
            )
        
        if not explanations:
            explanations.append("✅ No significant scam indicators detected")
        
        return explanations
    
    def _generate_recommendations(self, classification: str, 
                                  triggered_rules: List[str], 
                                  lang_info: Dict) -> List[str]:
        """Generate safety recommendations"""
        recommendations = []
        
        if classification == "SCAM":
            recommendations.extend([
                "🚫 DO NOT respond to this message or take any action",
                "🗑️ Delete this message immediately",
                "📢 Report as spam/scam to your service provider"
            ])
        elif classification == "SUSPICIOUS":
            recommendations.extend([
                "⚠️ Exercise extreme caution with this message",
                "🔍 Verify sender through official channels only",
                "❌ Do NOT click links or provide information"
            ])
        else:
            recommendations.append(
                "✅ Message appears safe, but always verify important requests"
            )
        
        # Context-specific recommendations
        if 'sensitive_data_request' in triggered_rules:
            recommendations.append(
                "🔒 NEVER share OTP, PIN, passwords, or CVV via message"
            )
        
        if 'brand_impersonation_pakistan_financial' in triggered_rules:
            recommendations.append(
                "📱 Verify through official app (Easypaisa/JazzCash)"
            )
        
        if 'shortened_url' in triggered_rules:
            recommendations.append(
                "🔗 NEVER click shortened URLs - they hide the destination"
            )
        
        return recommendations
    
    def _generate_hash(self, message: str) -> str:
        """Generate unique message hash"""
        import hashlib
        return hashlib.sha256(message.encode()).hexdigest()[:16]


# Initialize detection engine (singleton)
engine = DetectionEngine()


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """API information endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "status": "active",
        "features": {
            "ml_detection": settings.ENABLE_ML,
            "rule_detection": True,
            "multi_language": True,
            "screenshot_detection": settings.ENABLE_SCREENSHOT_DETECTION,
            "analytics": settings.ENABLE_ANALYTICS
        },
        "endpoints": {
            "analyze": "POST /analyze - Analyze text messages",
            "screenshot": "POST /analyze-screenshot - Analyze screenshots",
            "analytics": "GET /analytics - Get statistics",
            "threats": "GET /threat-intelligence - Get threat intel",
            "health": "GET /health - Health check"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": settings.VERSION,
        "ml_enabled": settings.ENABLE_ML,
        "analytics_enabled": settings.ENABLE_ANALYTICS
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(request: MessageRequest):
    """
    Analyze message for scam indicators
    
    Args:
        request: MessageRequest with message text
        
    Returns:
        AnalysisResponse with complete analysis
    """
    if not request.message or len(request.message.strip()) == 0:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    if len(request.message) > settings.MAX_MESSAGE_LENGTH:
        raise HTTPException(
            status_code=400, 
            detail=f"Message too long (max {settings.MAX_MESSAGE_LENGTH} characters)"
        )
    
    try:
        result = engine.analyze_message(request.message, request.language)
        return AnalysisResponse(**result)
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis failed")


@app.post("/analyze-screenshot", response_model=ScreenshotResponse)
async def analyze_screenshot(request: ScreenshotRequest):
    """Analyze payment screenshot for authenticity"""
    if not settings.ENABLE_SCREENSHOT_DETECTION:
        raise HTTPException(
            status_code=503, 
            detail="Screenshot detection is not enabled"
        )
    
    if not engine.screenshot_analyzer:
        raise HTTPException(
            status_code=503,
            detail="Screenshot analyzer not initialized"
        )
    
    try:
        result = engine.screenshot_analyzer.analyze(request.extracted_text)
        return ScreenshotResponse(**result)
        
    except Exception as e:
        logger.error(f"Screenshot analysis error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Screenshot analysis failed")


@app.get("/analytics")
async def get_analytics(hours: int = 24):
    """Get analytics for specified time period"""
    if not settings.ENABLE_ANALYTICS:
        raise HTTPException(status_code=503, detail="Analytics not enabled")
    
    if hours < 1 or hours > 168:
        raise HTTPException(
            status_code=400, 
            detail="Hours must be between 1 and 168"
        )
    
    try:
        stats = engine.analytics.get_statistics(hours=hours)
        return stats
        
    except Exception as e:
        logger.error(f"Analytics error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analytics failed")


@app.get("/threat-intelligence")
async def get_threat_intelligence():
    """Get threat intelligence report"""
    if not settings.ENABLE_ANALYTICS:
        raise HTTPException(status_code=503, detail="Analytics not enabled")
    
    try:
        intelligence = engine.threat_intel.generate_report()
        return intelligence
        
    except Exception as e:
        logger.error(f"Threat intelligence error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Threat intelligence failed")


@app.on_event("startup")
async def startup_event():
    """Run on application startup"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    logger.info(f"ML Detection: {'Enabled' if settings.ENABLE_ML else 'Disabled'}")
    logger.info(f"Analytics: {'Enabled' if settings.ENABLE_ANALYTICS else 'Disabled'}")
    logger.info(f"Screenshot Detection: {'Enabled' if settings.ENABLE_SCREENSHOT_DETECTION else 'Disabled'}")


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown"""
    logger.info("Shutting down ScamShield AI")


if __name__ == "__main__":
    import uvicorn
    
    print("=" * 70)
    print(f"🛡️  {settings.APP_NAME} v{settings.VERSION}")
    print("=" * 70)
    print("✨ Features:")
    print(f"   • ML Detection: {'Enabled' if settings.ENABLE_ML else 'Disabled'}")
    print(f"   • Rule Detection: Enabled")
    print(f"   • Multi-language: Enabled")
    print(f"   • Screenshot Detection: {'Enabled' if settings.ENABLE_SCREENSHOT_DETECTION else 'Disabled'}")
    print(f"   • Analytics: {'Enabled' if settings.ENABLE_ANALYTICS else 'Disabled'}")
    print("=" * 70)
    print(f"🌐 Server: http://0.0.0.0:{settings.PORT}")
    print(f"📚 API Docs: http://localhost:{settings.PORT}/docs")
    print("=" * 70)
    
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower()
    )
