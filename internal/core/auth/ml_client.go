package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/u11336/ai-iam/internal/data/models"
)

// MLClient handles communication with the ML service
type MLClient struct {
	baseURL    string
	httpClient *http.Client
	enabled    bool
}

// MLPredictionRequest represents the request to ML service
type MLPredictionRequest struct {
	UserID    int64  `json:"user_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	Success   bool   `json:"success"`
}

// MLPredictionResponse represents the response from ML service
type MLPredictionResponse struct {
	RiskScore           float64  `json:"risk_score"`
	AnomalyType         string   `json:"anomaly_type"`
	Confidence          float64  `json:"confidence"`
	ContributingFactors []string `json:"contributing_factors"`
}

// NewMLClient creates a new ML service client
func NewMLClient(baseURL string, enabled bool) *MLClient {
	return &MLClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second, // 5 second timeout for ML predictions
		},
		enabled: enabled,
	}
}

// PredictAnomaly calls the ML service for anomaly prediction
func (c *MLClient) PredictAnomaly(accessLog *models.AccessLog) (float64, string, error) {
	if !c.enabled {
		// Fallback to statistical methods when ML service is disabled
		return c.statisticalFallback(accessLog), "statistical_fallback", nil
	}

	// Prepare request
	request := MLPredictionRequest{
		UserID:    accessLog.UserID,
		IPAddress: accessLog.IPAddress,
		UserAgent: accessLog.UserAgent,
		Resource:  accessLog.Resource,
		Action:    accessLog.Action,
		Timestamp: accessLog.Timestamp.Format(time.RFC3339),
		Success:   accessLog.Success,
	}

	// Marshal request
	jsonData, err := json.Marshal(request)
	if err != nil {
		return c.statisticalFallback(accessLog), "marshal_error", err
	}

	// Make HTTP request to ML service
	resp, err := c.httpClient.Post(
		fmt.Sprintf("%s/predict", c.baseURL),
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		// Fallback to statistical methods on ML service failure
		return c.statisticalFallback(accessLog), "ml_service_unavailable", err
	}
	defer resp.Body.Close()

	// Check if ML service is healthy
	if resp.StatusCode != http.StatusOK {
		return c.statisticalFallback(accessLog), "ml_service_error",
			fmt.Errorf("ML service returned status %d", resp.StatusCode)
	}

	// Parse response
	var mlResponse MLPredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&mlResponse); err != nil {
		return c.statisticalFallback(accessLog), "response_parse_error", err
	}

	return mlResponse.RiskScore, mlResponse.AnomalyType, nil
}

// statisticalFallback provides basic statistical anomaly detection when ML service is unavailable
func (c *MLClient) statisticalFallback(accessLog *models.AccessLog) float64 {
	riskScore := 0.0

	// Basic heuristics for risk calculation
	currentHour := time.Now().Hour()

	// Time-based risk (simple heuristic)
	if currentHour < 6 || currentHour > 22 {
		riskScore += 0.3 // Higher risk for off-hours access
	}

	// Weekend access
	if time.Now().Weekday() == time.Saturday || time.Now().Weekday() == time.Sunday {
		riskScore += 0.2
	}

	// IP-based risk (simplified)
	if accessLog.IPAddress != "" {
		// Could implement basic IP reputation checking here
		riskScore += 0.1
	}

	// Ensure risk score is within bounds
	if riskScore > 1.0 {
		riskScore = 1.0
	}

	return riskScore
}

// HealthCheck checks if ML service is available
func (c *MLClient) HealthCheck() error {
	if !c.enabled {
		return fmt.Errorf("ML service is disabled")
	}

	resp, err := c.httpClient.Get(fmt.Sprintf("%s/health", c.baseURL))
	if err != nil {
		return fmt.Errorf("ML service health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ML service health check returned status %d", resp.StatusCode)
	}

	return nil
}
