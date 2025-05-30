package auth

import (
	"math"
	"strings"
	"time"

	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
)

// AnomalyDetector detects anomalies in user access patterns
type AnomalyDetector struct {
	auditRepo *repository.AuditRepository
	mlClient  *MLClient // Add ML client
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(auditRepo *repository.AuditRepository, mlServiceURL string, mlEnabled bool) *AnomalyDetector {
	return &AnomalyDetector{
		auditRepo: auditRepo,
		mlClient:  NewMLClient(mlServiceURL, mlEnabled),
	}
}

// CalculateRiskScore calculates a risk score for an access attempt
// Returns a score between 0.0 (no risk) and 1.0 (high risk), and the type of anomaly detected
func (d *AnomalyDetector) CalculateRiskScore(accessLog *models.AccessLog) (float64, string) {

	// First, try ML service for advanced anomaly detection
	mlRiskScore, anomalyType, err := d.mlClient.PredictAnomaly(accessLog)
	if err == nil {
		// ML service succeeded, use its prediction
		return mlRiskScore, anomalyType
	}

	// ML service failed, fall back to existing statistical methods
	// Get historical access patterns for this user
	patterns, err := d.auditRepo.GetUserAccessPattern(accessLog.UserID, 30) // 30 days lookback
	if err != nil || len(patterns) == 0 {
		// If no history or error, assign a moderate risk score
		return 0.5, "insufficient_history"
	}

	// Calculate risk components
	timeRisk := d.calculateTimeRisk(accessLog, patterns)
	locationRisk := d.calculateLocationRisk(accessLog, patterns)
	resourceRisk := d.calculateResourceRisk(accessLog, patterns)
	behaviorRisk := d.calculateBehaviorRisk(accessLog, patterns)

	// Calculate final risk score - weighted average
	riskScore := (timeRisk*0.25 + locationRisk*0.35 + resourceRisk*0.2 + behaviorRisk*0.2)

	// Determine the primary anomaly type
	anomalyType = "statistical_analysis"
	maxRisk := math.Max(math.Max(timeRisk, locationRisk), math.Max(resourceRisk, behaviorRisk))

	if maxRisk > 0.7 {
		switch {
		case timeRisk == maxRisk:
			anomalyType = "time"
		case locationRisk == maxRisk:
			anomalyType = "location"
		case resourceRisk == maxRisk:
			anomalyType = "resource"
		case behaviorRisk == maxRisk:
			anomalyType = "behavior"
		}
	}

	return riskScore, anomalyType
}

// calculateTimeRisk evaluates the risk based on access time patterns
func (d *AnomalyDetector) calculateTimeRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	if len(history) < 5 {
		return 0.5 // Moderate risk for insufficient history
	}

	// Calculate normal time of access (in minutes from midnight)
	var timeSum int
	var timeFrequency = make(map[int]int)
	var dayFrequency = make(map[int]int)

	for _, log := range history {
		timeSum += log.AccessTime
		timeFrequency[log.AccessTime/60]++ // Group by hour
		dayFrequency[log.DayOfWeek]++
	}

	avgTime := timeSum / len(history)
	currentTime := current.AccessTime
	timeDiff := math.Abs(float64(currentTime - avgTime))

	// Time difference risk (0-1)
	// Consider anything more than 6 hours from average as high risk
	timeRisk := math.Min(timeDiff/360.0, 1.0)

	// Check if current day of week is common
	dayRisk := 0.0
	if dayFrequency[current.DayOfWeek] < len(history)/10 {
		dayRisk = 0.8 // Uncommon day
	}

	// Check if current hour is common
	hourRisk := 0.0
	if timeFrequency[current.AccessTime/60] < len(history)/10 {
		hourRisk = 0.7 // Uncommon hour
	}

	// Combine risks
	return math.Max(timeRisk, math.Max(dayRisk, hourRisk))
}

// calculateLocationRisk evaluates the risk based on IP address
func (d *AnomalyDetector) calculateLocationRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	if len(history) < 5 {
		return 0.5 // Moderate risk for insufficient history
	}

	// Count IP frequency
	ipFrequency := make(map[string]int)
	for _, log := range history {
		ipFrequency[log.IPAddress]++
	}

	// Check if current IP is in history
	if frequency, exists := ipFrequency[current.IPAddress]; exists {
		// Calculate how common this IP is
		frequencyRatio := float64(frequency) / float64(len(history))
		// If IP is used in less than 10% of accesses, consider it unusual
		if frequencyRatio < 0.1 {
			return 0.8
		}
		// If IP is used in less than 30% of accesses, consider it somewhat unusual
		if frequencyRatio < 0.3 {
			return 0.5
		}
		return 0.1 // Common IP address
	}

	// IP not in history at all - high risk
	return 0.9
}

// calculateResourceRisk evaluates if accessing unusual resources
func (d *AnomalyDetector) calculateResourceRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	if len(history) < 5 {
		return 0.4 // Slightly below moderate risk for insufficient history
	}

	// Count resource frequency
	resourceFrequency := make(map[string]int)
	for _, log := range history {
		resourceFrequency[log.Resource]++
	}

	// Check if current resource is in history
	if frequency, exists := resourceFrequency[current.Resource]; exists {
		// Calculate how common this resource is
		frequencyRatio := float64(frequency) / float64(len(history))
		// If resource is accessed in less than 5% of accesses, consider it unusual
		if frequencyRatio < 0.05 {
			return 0.7
		}
		// If resource is accessed in less than 20% of accesses, consider it somewhat unusual
		if frequencyRatio < 0.2 {
			return 0.4
		}
		return 0.1 // Common resource
	}

	// Resource not in history at all - moderately high risk
	return 0.7
}

// calculateBehaviorRisk evaluates overall behavior patterns
func (d *AnomalyDetector) calculateBehaviorRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	if len(history) < 10 {
		return 0.3 // Lower moderate risk for insufficient history
	}

	// Check user agent consistency
	userAgentRisk := d.calculateUserAgentRisk(current, history)

	// Check access frequency
	frequencyRisk := d.calculateFrequencyRisk(current, history)

	// Check for unusual patterns in resource access sequence
	sequenceRisk := d.calculateSequenceRisk(current, history)

	// Combine the risks
	return math.Max(userAgentRisk, math.Max(frequencyRisk, sequenceRisk))
}

// calculateUserAgentRisk checks if the user agent is consistent with history
func (d *AnomalyDetector) calculateUserAgentRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	userAgentTypes := make(map[string]int)

	// Simple classification of user agent types
	for _, log := range history {
		agentType := classifyUserAgent(log.UserAgent)
		userAgentTypes[agentType]++
	}

	// Check if current user agent type is common
	currentType := classifyUserAgent(current.UserAgent)
	if frequency, exists := userAgentTypes[currentType]; exists {
		frequencyRatio := float64(frequency) / float64(len(history))
		if frequencyRatio < 0.1 {
			return 0.7 // Unusual user agent type
		}
		return 0.1 // Common user agent type
	}

	// User agent type not in history
	return 0.8
}

// calculateFrequencyRisk checks for unusual access frequency
func (d *AnomalyDetector) calculateFrequencyRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	// Sort history by timestamp (assuming history is already sorted by timestamp desc)
	if len(history) < 2 {
		return 0.3
	}

	// Check if this access is unusually soon after the last one
	lastAccess := history[0].Timestamp
	timeSinceLast := time.Since(lastAccess)

	// If less than 1 minute since last access, could be suspicious
	if timeSinceLast < time.Minute {
		return 0.7
	}

	// Calculate average time between accesses
	var totalGap time.Duration
	for i := 0; i < len(history)-1; i++ {
		gap := history[i].Timestamp.Sub(history[i+1].Timestamp)
		totalGap += gap
	}
	avgGap := totalGap / time.Duration(len(history)-1)

	// If this access is much sooner than average, it might be suspicious
	if avgGap > time.Minute*10 && timeSinceLast < avgGap/5 {
		return 0.6
	}

	return 0.1
}

// calculateSequenceRisk checks for unusual patterns in resource access sequence
func (d *AnomalyDetector) calculateSequenceRisk(current *models.AccessLog, history []*models.AccessLog) float64 {
	// This is a simplified implementation
	// In a real system, you'd want to implement more sophisticated pattern recognition

	// Check if current action follows a common pattern
	if len(history) < 3 {
		return 0.2
	}

	// Look for the current resource in common sequences
	commonResource := false
	for i := 0; i < len(history)-2; i++ {
		if history[i].Resource == current.Resource {
			commonResource = true
			break
		}
	}

	if !commonResource {
		return 0.5 // Uncommon resource in sequence
	}

	return 0.1
}

// classifyUserAgent returns a simple classification of the user agent
func classifyUserAgent(userAgent string) string {
	userAgent = strings.ToLower(userAgent)

	switch {
	case strings.Contains(userAgent, "mobile"):
		return "mobile"
	case strings.Contains(userAgent, "tablet"):
		return "tablet"
	case strings.Contains(userAgent, "windows"):
		return "windows"
	case strings.Contains(userAgent, "mac"):
		return "mac"
	case strings.Contains(userAgent, "linux"):
		return "linux"
	case strings.Contains(userAgent, "android"):
		return "android"
	case strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ipad"):
		return "ios"
	case strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "crawler"):
		return "bot"
	default:
		return "other"
	}
}
