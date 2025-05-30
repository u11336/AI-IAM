# AI-Powered Identity and Access Management (IAM) System

An intelligent, AI-powered Identity and Access Management (IAM) system built with Go and Python. The system combines traditional security controls with advanced machine learning algorithms for behavioral analysis and anomaly detection.

## 🚀 Features

### Core Security Features
- **Secure User Authentication**: JWT-based token authentication with bcrypt password hashing
- **Multi-Factor Authentication (MFA)**: TOTP-based MFA support with QR code generation
- **Role-Based Access Control (RBAC)**: Flexible role and permission management system
- **Comprehensive Audit Logging**: Complete audit trail of all security-related events

### AI/ML-Powered Features
- **Real-time Anomaly Detection**: Machine learning models for detecting suspicious user behavior
- **Behavioral Analytics**: Pattern recognition using multiple ML algorithms:
  - Isolation Forest for unsupervised anomaly detection
  - Random Forest for supervised classification
  - DBSCAN clustering for outlier detection
- **Risk-Adaptive Security**: Dynamic security responses based on calculated risk scores
- **Feature Engineering**: Advanced feature extraction from user access patterns

### System Architecture
- **Microservices Design**: Separate Go application and Python ML service
- **Containerized Deployment**: Docker and Docker Compose support
- **Graceful Degradation**: Fallback to statistical methods when ML service is unavailable
- **RESTful API**: Clean API design with comprehensive endpoint coverage

## 🏗️ Technical Architecture

### Backend Services
- **Main Application**: Go (Golang) 1.24+ with Chi router
- **ML Service**: Python 3.11+ with FastAPI and scikit-learn
- **Database**: SQLite (easily replaceable with PostgreSQL or MySQL)
- **Authentication**: JWT with RS256 signing
- **Containerization**: Docker with multi-stage builds

### ML Pipeline
- **Feature Engineering**: Time-based, location-based, and behavioral features
- **Model Training**: Automated retraining with new data
- **Real-time Inference**: Sub-100ms prediction latency
- **Model Persistence**: Joblib-based model serialization

## 📁 Project Structure

------
ai-iam/
├── cmd/server/                   # Go application entry point
├── internal/                     # Go application core
│   ├── api/                      # HTTP handlers and middleware
│   ├── core/                     # Business logic (auth, rbac)
│   ├── data/                     # Data models and repositories
│   └── utils/                    # Utility functions
├── ml-service/                   # Python ML microservice
│   ├── app/                      # FastAPI application
│   ├── models/                   # Trained ML models
│   └── requirements.txt
├── scripts/                      # Setup and utility scripts
------

## 🚀 Quick Start

### Prerequisites

- Go 1.24 or higher
- Python 3.11+ (for ML service)
- Docker and Docker Compose
- Git

### Installation

1. **Clone the repository:**
   ------bash
   git clone https://github.com/u11336/ai-iam.git
   cd ai-iam
   ------

2. **Set up configuration:**
   ------bash
   cp config.example.json config.json
   # Edit config.json with your settings
   ------

3. **Run with Docker Compose (Recommended):**
   ------bash
   docker-compose up --build
   ------

4. **Or run services separately:**
   ------bash
   # Terminal 1: ML Service
   cd ml-service
   pip install -r requirements.txt
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
   
   # Terminal 2: Go Application
   export ML_SERVICE_URL=http://localhost:8001
   go run cmd/server/main.go
   ------

### First Steps

1. **Check service health:**
   ------bash
   curl http://localhost:8080/health
   curl http://localhost:8001/health
   ------

2. **Register a user:**
   ------bash
   curl -X POST http://localhost:8080/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "StrongP@ssw0rd!"
     }'
   ------

3. **Login and get JWT token:**
   ------bash
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "password": "StrongP@ssw0rd!"
     }'
   ------

## 🤖 AI/ML Features

### Anomaly Detection Models

1. **Isolation Forest**: Unsupervised anomaly detection
   - Detects outliers in user behavior patterns
   - No labeled data required
   - Effective for detecting novel attack patterns

2. **Random Forest Classifier**: Supervised learning
   - Uses historical labeled anomaly data
   - Provides probability scores for anomalies
   - High accuracy when training data is available

3. **DBSCAN Clustering**: Density-based outlier detection
   - Identifies users with unusual behavior clusters
   - Effective for detecting coordinated attacks
   - Adapts to changing user behavior patterns

### Feature Engineering

The system extracts and analyzes multiple behavioral features:

- **Temporal Features**: Hour of day, day of week, access frequency
- **Location Features**: IP address patterns, geographic distance
- **Resource Features**: Resource access diversity, unusual resource requests
- **Behavioral Features**: Session patterns, device consistency, user agent analysis

### Risk Scoring

Risk scores are calculated using ensemble methods:
- Weighted combination of multiple model outputs
- Confidence scoring based on model agreement
- Adaptive thresholds based on user profiles

## 🛠️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IAM_PORT` | Server port | 8080 |
| `IAM_DB_PATH` | Database path | app/data/iam.db |
| `IAM_JWT_SECRET` | JWT signing secret | (required) |
| `ML_SERVICE_URL` | ML service URL | http://localhost:8001 |

### Configuration File

------json
{
  "port": 8080,
  "database_path": "app/data/iam.db",
  "jwt_secret": "your-secret-key",
  "jwt_expiration_hours": 24,
  "mfa_enabled": true,
  "anomaly_detection_on": true,
  "ml_service_enabled": true,
  "ml_service_url": "http://ml-service:8001",
  "risk_threshold_low": 0.3,
  "risk_threshold_medium": 0.6,
  "risk_threshold_high": 0.9
}
------

## 🐳 Docker Deployment

### Single Command Deployment

------bash
docker-compose up --build
------

### Production Deployment

1. **Build optimized images:**
   ------bash
   docker-compose -f docker-compose.prod.yml build
   ------

2. **Deploy with environment-specific configuration:**
   ------bash
   docker-compose -f docker-compose.prod.yml up -d
   ------

### Container Sizes

- **Go Application Container**: 96 MB (optimized multi-stage build)
- **ML Service Container**: ~450 MB (includes Python + ML libraries)
- **Source Code Size**: 13.5 MB

## 📊 Monitoring & Observability

### Health Checks

Both services provide health check endpoints:
- Go Service: `GET /health`
- ML Service: `GET /health`

### Logging

- Structured JSON logging with contextual information
- Configurable log levels (DEBUG, INFO, WARN, ERROR)
- Request correlation IDs for distributed tracing

### Metrics

Key metrics tracked:
- Authentication success/failure rates
- Anomaly detection rates
- API response times
- ML model prediction latency

## 🔒 Security Features

### Authentication & Authorization
- JWT-based stateless authentication
- Role-based access control (RBAC)
- Multi-factor authentication (TOTP)
- Password strength enforcement

### Anomaly Detection
- Real-time behavioral analysis
- Adaptive risk scoring
- Automated threat response
- False positive reduction through ML

### Data Protection
- Encrypted sensitive data storage
- Secure password hashing (bcrypt)
- SQL injection prevention
- Input validation and sanitization

## 🧪 Testing

### Running Tests

------bash
# Go application tests
go test ./...

# ML service tests
cd ml-service
python -m pytest tests/

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
------

### Test Coverage

- Unit tests for core business logic
- Integration tests for API endpoints
- ML model validation tests
- Load testing for performance validation

## 📈 Performance

### Benchmarks

- **Authentication latency**: < 50ms (p95)
- **Anomaly detection**: < 100ms (p95)
- **Throughput**: 1000+ requests/second
- **ML prediction**: < 20ms average

### Scalability

- Horizontal scaling through container orchestration
- Stateless architecture for easy load balancing
- Database connection pooling
- Efficient caching strategies

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built following NIST 800-207 Zero Trust Architecture principles
- Implements OWASP security best practices
- Uses industry-standard ML algorithms for behavioral analysis
- Inspired by modern DevSecOps practices

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/u11336/ai-iam/issues)
- **Discussions**: [GitHub Discussions](https://github.com/u11336/ai-iam/discussions)

---

**AI-IAM System** - Intelligent Identity and Access Management for the Modern Enterprise