import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from typing import Dict, List, Tuple, Optional
import os

class AnomalyDetector:
    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = StandardScaler()
        self.dbscan = None
        self.feature_names = [
            'hour_of_day', 'day_of_week', 'login_frequency_last_24h',
            'unique_ips_last_week', 'failed_attempts_last_hour',
            'resource_diversity_score', 'session_duration_avg',
            'geographic_distance', 'device_consistency_score',
            'time_since_last_login', 'access_pattern_deviation'
        ]
        self.model_path = "models/"
        self.logger = logging.getLogger(__name__)
        
    def prepare_features(self, access_data: List[Dict]) -> pd.DataFrame:
        #Preparing features for ML model
        df = pd.DataFrame(access_data)
        
        # Getting time features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Aggregated features by user
        user_features = []
        
        for user_id in df['user_id'].unique():
            user_data = df[df['user_id'] == user_id].sort_values('timestamp')
            
            # Login frequency for the last 24h
            recent_logins = len(user_data[user_data['timestamp'] > 
                                       user_data['timestamp'].max() - pd.Timedelta(hours=24)])
            
            #Unique IP for the last week
            unique_ips = user_data['ip_address'].nunique()
            
            # Fail attempts last hour
            failed_attempts = len(user_data[
                (user_data['success'] == False) & 
                (user_data['timestamp'] > user_data['timestamp'].max() - pd.Timedelta(hours=1))
            ])
            
            # Resource diversity
            resource_diversity = user_data['resource'].nunique()
            
            # Average session time (imitating)
            session_duration_avg = np.random.normal(30, 10)  # minutes
            
            # Geo distance
            geographic_distance = self._calculate_geographic_distance(user_data['ip_address'])
            
            # Device consistency
            device_consistency = user_data['user_agent'].value_counts().max() / len(user_data)
            
            # Time from last login
            time_since_last = (user_data['timestamp'].max() - 
                             user_data['timestamp'].shift(1).max()).total_seconds() / 3600
            
            # Access pattern deviations
            access_pattern_deviation = self._calculate_pattern_deviation(user_data)
            
            for _, row in user_data.iterrows():
                user_features.append({
                    'user_id': user_id,
                    'hour_of_day': row['timestamp'].hour,
                    'day_of_week': row['timestamp'].dayofweek,
                    'login_frequency_last_24h': recent_logins,
                    'unique_ips_last_week': unique_ips,
                    'failed_attempts_last_hour': failed_attempts,
                    'resource_diversity_score': resource_diversity,
                    'session_duration_avg': session_duration_avg,
                    'geographic_distance': geographic_distance,
                    'device_consistency_score': device_consistency,
                    'time_since_last_login': time_since_last if not pd.isna(time_since_last) else 0,
                    'access_pattern_deviation': access_pattern_deviation,
                    'is_anomaly': row.get('is_anomaly', 0) # for learning
                })
        
        return pd.DataFrame(user_features)
    
    def _calculate_geographic_distance(self, ip_addresses: pd.Series) -> float:
        # IP geolocating
        return np.random.uniform(0, 1000)
    
    def _calculate_pattern_deviation(self, user_data: pd.DataFrame) -> float:
        #Calculating Deviations from access pattern
        if len(user_data) < 2:
            return 0
        
        # Access time analysis
        hours = user_data['timestamp'].dt.hour
        hour_std = hours.std()
        
        # Resurce Analysis
        resource_pattern = user_data['resource'].value_counts(normalize=True).entropy()
        
        return hour_std + resource_pattern
    
    def train_models(self, training_data: List[Dict]) -> Dict[str, float]:
        #Teaching ML models

        self.logger.info("Starting model training...")
        
        # Data preparation
        df = self.prepare_features(training_data)
        
        if df.empty:
            raise ValueError("No training data available")
        
        # Selection of features and target variable
        X = df[self.feature_names]
        y = df['is_anomaly'] if 'is_anomaly' in df.columns else None
        
        # Normalizing features
        X_scaled = self.scaler.fit_transform(X)
        
        # 1. Teaching Isolation Forest (unsupervised)
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_scaled)
        
        # 2. Clastering with DBSCAN
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.dbscan.fit(X_scaled)
        
        metrics = {}
        
        # 3. Teaching Random Forest
        if y is not None and y.sum() > 0:
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42, stratify=y
            )
            
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight='balanced'
            )
            self.random_forest.fit(X_train, y_train)
            
            # Performance check
            y_pred = self.random_forest.predict(X_test)
            metrics['random_forest_accuracy'] = (y_pred == y_test).mean()
            
            self.logger.info(f"Random Forest Accuracy: {metrics['random_forest_accuracy']:.4f}")
            self.logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        
        # Saving models
        self.save_models()
        
        metrics['isolation_forest_anomalies'] = (self.isolation_forest.predict(X_scaled) == -1).sum()
        metrics['dbscan_clusters'] = len(set(self.dbscan.labels_)) - (1 if -1 in self.dbscan.labels_ else 0)
        
        self.logger.info("Model training completed successfully")
        return metrics
    
    def predict_anomaly(self, access_data: Dict) -> Dict[str, float]:
        #Anomaly prediction for one access ocasion
        
        # Preparing features
        df = self.prepare_features([access_data])
        if df.empty:
            return {'risk_score': 0.5, 'anomaly_type': 'insufficient_data'}
        
        X = df[self.feature_names].iloc[-1:] # Last record
        X_scaled = self.scaler.transform(X)
        
        risk_scores = []
        anomaly_types = []
        
        # Isolation Forest
        if self.isolation_forest:
            iso_score = self.isolation_forest.decision_function(X_scaled)[0]
            iso_anomaly = self.isolation_forest.predict(X_scaled)[0] == -1
            
            # Turning to probability (0-1)
            iso_risk = max(0, min(1, (0.5 - iso_score) * 2))
            risk_scores.append(iso_risk)
            
            if iso_anomaly:
                anomaly_types.append('isolation_forest')
        
        # Random Forest
        if self.random_forest:
            rf_proba = self.random_forest.predict_proba(X_scaled)[0]
            rf_risk = rf_proba[1] if len(rf_proba) > 1 else 0.5
            risk_scores.append(rf_risk)
            
            if rf_risk > 0.7:
                anomaly_types.append('supervised_learning')
        
        # DBSCAN clastering
        if self.dbscan:
            cluster = self.dbscan.fit_predict(X_scaled)[0]
            if cluster == -1:  # Dropout
                risk_scores.append(0.8)
                anomaly_types.append('clustering_outlier')
        
        # Final risk evaluation
        final_risk = np.mean(risk_scores) if risk_scores else 0.5
        primary_anomaly_type = anomaly_types[0] if anomaly_types else 'normal'
        
        return {
            'risk_score': float(final_risk),
            'anomaly_type': primary_anomaly_type,
            'confidence': len(risk_scores) / 3.0,  # Trust based on the number or models
            'contributing_factors': anomaly_types
        }
    
    def save_models(self):
        #Saving taught models
        os.makedirs(self.model_path, exist_ok=True)
        
        if self.isolation_forest:
            joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
        
        if self.random_forest:
            joblib.dump(self.random_forest, f"{self.model_path}/random_forest.pkl")
        
        if self.dbscan:
            joblib.dump(self.dbscan, f"{self.model_path}/dbscan.pkl")
        
        joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
        
        self.logger.info("Models saved successfully")
    
    def load_models(self):
        #Loading saved models
        try:
            if os.path.exists(f"{self.model_path}/isolation_forest.pkl"):
                self.isolation_forest = joblib.load(f"{self.model_path}/isolation_forest.pkl")
            
            if os.path.exists(f"{self.model_path}/random_forest.pkl"):
                self.random_forest = joblib.load(f"{self.model_path}/random_forest.pkl")
            
            if os.path.exists(f"{self.model_path}/dbscan.pkl"):
                self.dbscan = joblib.load(f"{self.model_path}/dbscan.pkl")
            
            if os.path.exists(f"{self.model_path}/scaler.pkl"):
                self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
            
            self.logger.info("Models loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            return False