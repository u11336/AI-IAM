from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional
import logging
import traceback
from .models.anomaly_detector import AnomalyDetector
import uvicorn

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI-IAM ML Service", version="1.0.0")

# Global detector
detector = AnomalyDetector()

class AccessLogData(BaseModel):
    user_id: int
    ip_address: str
    user_agent: str
    resource: str
    action: str
    timestamp: str
    success: bool
    risk_score: Optional[float] = None
    is_anomaly: Optional[int] = None

class TrainingData(BaseModel):
    access_logs: List[AccessLogData]

class AnomalyPredictionRequest(BaseModel):
    user_id: int
    ip_address: str
    user_agent: str
    resource: str
    action: str
    timestamp: str
    success: bool

class AnomalyPredictionResponse(BaseModel):
    risk_score: float
    anomaly_type: str
    confidence: float
    contributing_factors: List[str]

@app.on_event("startup")
async def startup_event():
    """Loading models on service startup"""
    logger.info("Starting AI-IAM ML Service...")
    try:
        detector.load_models()
        logger.info("ML Service ready")
    except Exception as e:
        logger.error(f"Error loading models on startup: {e}")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "AI-IAM ML Service",
        "models_loaded": {
            "isolation_forest": detector.isolation_forest is not None,
            "random_forest": detector.random_forest is not None,
            "dbscan": detector.dbscan is not None,
            "is_trained": detector.is_trained
        }
    }

@app.post("/train")
async def train_models(training_data: TrainingData, background_tasks: BackgroundTasks):
    """ML models learning"""
    try:
        # Convert data
        training_logs = []
        for log in training_data.access_logs:
            log_dict = log.dict()
            training_logs.append(log_dict)
        
        logger.info(f"Received {len(training_logs)} training samples")
        
        # Train models synchronously for now (can be made async later)
        metrics = detector.train_models(training_logs)
        
        return {
            "message": "Model training completed",
            "training_samples": len(training_logs),
            "metrics": metrics
        }
    except Exception as e:
        logger.error(f"Training error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

@app.post("/predict", response_model=AnomalyPredictionResponse)
async def predict_anomaly(request: AnomalyPredictionRequest):
    """Anomaly prediction of access"""
    try:
        # Convert request to prediction format
        access_data = request.dict()
        
        logger.info(f"Predicting anomaly for user {access_data['user_id']} from IP {access_data['ip_address']}")
        
        # Get prediction
        prediction = detector.predict_anomaly(access_data)
        
        logger.info(f"Prediction result: risk_score={prediction['risk_score']}, type={prediction['anomaly_type']}")
        
        return AnomalyPredictionResponse(**prediction)
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Return a safe fallback prediction instead of raising exception
        return AnomalyPredictionResponse(
            risk_score=0.5,
            anomaly_type="prediction_error",
            confidence=0.0,
            contributing_factors=[f"error: {str(e)}"]
        )

@app.get("/models/status")
async def get_models_status():
    """Status of loaded models"""
    try:
        return {
            "isolation_forest_loaded": detector.isolation_forest is not None,
            "random_forest_loaded": detector.random_forest is not None,
            "dbscan_loaded": detector.dbscan is not None,
            "scaler_loaded": detector.scaler is not None,
            "is_trained": detector.is_trained,
            "feature_names": detector.feature_names
        }
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        return {
            "isolation_forest_loaded": False,
            "random_forest_loaded": False,
            "dbscan_loaded": False,
            "scaler_loaded": False,
            "is_trained": False,
            "error": str(e)
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)