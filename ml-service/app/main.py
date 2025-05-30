from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional
import logging
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
    #Loading models on service startup
    logger.info("Starting AI-IAM ML Service...")
    detector.load_models()
    logger.info("ML Service ready")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "AI-IAM ML Service"}

@app.post("/train")
async def train_models(training_data: TrainingData, background_tasks: BackgroundTasks):
    #ML models learning
    try:
        # Converting
        training_logs = [log.dict() for log in training_data.access_logs]
        
        # Running learning in background
        background_tasks.add_task(detector.train_models, training_logs)
        
        return {
            "message": "Model training started",
            "training_samples": len(training_logs)
        }
    except Exception as e:
        logger.error(f"Training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict", response_model=AnomalyPredictionResponse)
async def predict_anomaly(request: AnomalyPredictionRequest):
    #Anomaly prediction of access
    try:
        # converting request to prediction format
        access_data = request.dict()
        
        # getting prediction
        prediction = detector.predict_anomaly(access_data)
        
        return AnomalyPredictionResponse(**prediction)
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/status")
async def get_models_status():
    #status of loaded models
    return {
        "isolation_forest_loaded": detector.isolation_forest is not None,
        "random_forest_loaded": detector.random_forest is not None,
        "dbscan_loaded": detector.dbscan is not None,
        "scaler_loaded": detector.scaler is not None
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)