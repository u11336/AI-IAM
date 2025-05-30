package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrAccountLocked         = errors.New("account is locked")
	ErrAccountInactive       = errors.New("account is inactive")
	ErrMFARequired           = errors.New("MFA verification required")
	ErrInvalidMFACode        = errors.New("invalid MFA code")
	ErrHighRiskDetected      = errors.New("high risk access attempt detected")
	ErrTokenGenerationFailed = errors.New("failed to generate token")
)

// AuthService handles authentication and authorization
type AuthService struct {
	userRepo        *repository.UserRepository
	auditRepo       *repository.AuditRepository
	jwtSecret       []byte
	jwtExpiration   time.Duration
	mfaEnabled      bool
	mfaIssuer       string
	anomalyDetector *AnomalyDetector
}

// AuthConfig holds authentication service configuration
type AuthConfig struct {
	JWTSecret        string
	JWTExpiration    time.Duration
	MFAEnabled       bool
	MFAIssuer        string
	AnomalyEnabled   bool
	MLServiceURL     string // Add ML service URL
	MLServiceEnabled bool   // Add ML service enable flag
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo *repository.UserRepository,
	auditRepo *repository.AuditRepository,
	config AuthConfig,
) *AuthService {
	anomalyDetector := NewAnomalyDetector(auditRepo, config.MLServiceURL, config.MLServiceEnabled)

	return &AuthService{
		userRepo:        userRepo,
		auditRepo:       auditRepo,
		jwtSecret:       []byte(config.JWTSecret),
		jwtExpiration:   config.JWTExpiration,
		mfaEnabled:      config.MFAEnabled,
		mfaIssuer:       config.MFAIssuer,
		anomalyDetector: anomalyDetector,
	}
}

// Login authenticates a user and returns a JWT token
func (s *AuthService) Login(request models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Lookup user
	user, err := s.userRepo.GetByUsername(request.Username)
	if err != nil {
		// Don't reveal if user exists or not to prevent enumeration attacks
		return nil, ErrInvalidCredentials
	}

	// Check if account is active
	if !user.IsActive {
		return nil, ErrAccountInactive
	}

	// Check if account is locked
	if user.IsLocked {
		return nil, ErrAccountLocked
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		// Increment failed login counter
		_ = s.userRepo.IncrementFailedLogin(request.Username)

		// Log failed attempt
		s.auditLoginAttempt(user.ID, ipAddress, userAgent, "failure", "Invalid password")

		return nil, ErrInvalidCredentials
	}

	// Check if MFA is required
	if s.mfaEnabled && user.MFAEnabled {
		if request.MFACode == "" {
			return &models.LoginResponse{
				MFARequired: true,
			}, ErrMFARequired
		}

		// Verify MFA code
		valid := totp.Validate(request.MFACode, user.MFASecret)
		if !valid {
			s.auditLoginAttempt(user.ID, ipAddress, userAgent, "failure", "Invalid MFA code")
			return nil, ErrInvalidMFACode
		}
	}

	// Calculate risk score for this login attempt
	accessLog := &models.AccessLog{
		UserID:     user.ID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Resource:   "auth",
		Action:     "login",
		AccessTime: timeOfDayInMinutes(time.Now()),
		DayOfWeek:  int(time.Now().Weekday()),
		Success:    true,
		Timestamp:  time.Now(), // Add timestamp for ML service
	}

	riskScore, anomalyType := s.anomalyDetector.CalculateRiskScore(accessLog)
	accessLog.RiskScore = riskScore

	// Enhanced risk-based decision making
	response := &models.LoginResponse{
		RiskScore: riskScore,
	}

	// Adaptive security responses based on ML predictions
	switch {
	case riskScore > 0.9:
		// Very high risk - block access and require admin review
		anomaly := &models.AnomalyDetection{
			UserID:      user.ID,
			AccessLogID: accessLog.ID,
			AnomalyType: anomalyType,
			RiskScore:   riskScore,
			ActionTaken: "block_admin_review",
		}
		_ = s.auditRepo.RecordAnomaly(anomaly)
		s.auditLoginAttempt(user.ID, ipAddress, userAgent, "blocked",
			fmt.Sprintf("Very high risk detected: %s (%.3f)", anomalyType, riskScore))
		return nil, ErrHighRiskDetected

	case riskScore > 0.8:
		// High risk - require additional verification
		if !user.MFAEnabled || request.MFACode == "" {
			anomaly := &models.AnomalyDetection{
				UserID:      user.ID,
				AccessLogID: accessLog.ID,
				AnomalyType: anomalyType,
				RiskScore:   riskScore,
				ActionTaken: "require_mfa",
			}
			_ = s.auditRepo.RecordAnomaly(anomaly)
			response.MFARequired = true
			response.RiskReason = fmt.Sprintf("High risk access pattern detected: %s", anomalyType)
			return response, ErrMFARequired
		}

	case riskScore > 0.6:
		// Medium risk - step up authentication and log
		anomaly := &models.AnomalyDetection{
			UserID:      user.ID,
			AccessLogID: accessLog.ID,
			AnomalyType: anomalyType,
			RiskScore:   riskScore,
			ActionTaken: "step_up_auth",
		}
		_ = s.auditRepo.RecordAnomaly(anomaly)

		// Could implement additional challenges here (email verification, security questions, etc.)
		response.RequiresStepUpAuth = true
		response.RiskReason = fmt.Sprintf("Medium risk detected: %s", anomalyType)

	case riskScore > 0.4:
		// Low-medium risk - enhanced monitoring
		anomaly := &models.AnomalyDetection{
			UserID:      user.ID,
			AccessLogID: accessLog.ID,
			AnomalyType: anomalyType,
			RiskScore:   riskScore,
			ActionTaken: "enhanced_monitoring",
		}
		_ = s.auditRepo.RecordAnomaly(anomaly)
		response.EnhancedMonitoring = true

	default:
		// Low risk - normal processing
		response.RiskLevel = "low"
	}

	// Save access log
	if err := s.auditRepo.CreateAccessLog(accessLog); err != nil {
		// Log the error but continue (non-critical)
		fmt.Printf("Error saving access log: %v\n", err)
	}

	// Generate JWT token
	token, err := s.generateToken(user)
	if err != nil {
		return nil, ErrTokenGenerationFailed
	}
	// Update response with token and user info
	response.Token = token

	response.User = &models.User{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		MFAEnabled: user.MFAEnabled,
		IsActive:   user.IsActive,
		IsLocked:   user.IsLocked,
		Roles:      user.Roles,
	}

	// Update last login and reset failed attempts
	_ = s.userRepo.UpdateLastLogin(user.ID)
	_ = s.userRepo.ResetFailedLoginCount(user.ID)

	// Log successful login with risk context
	s.auditLoginAttempt(user.ID, ipAddress, userAgent, "success",
		fmt.Sprintf("Risk score: %.3f, Type: %s", riskScore, anomalyType))

	return response, nil
}

// Method to check ML service health
func (s *AuthService) GetMLServiceStatus() map[string]interface{} {
	status := make(map[string]interface{})

	if s.anomalyDetector != nil && s.anomalyDetector.mlClient != nil {
		err := s.anomalyDetector.mlClient.HealthCheck()
		status["ml_service_available"] = err == nil
		status["ml_service_enabled"] = s.anomalyDetector.mlClient.enabled
		if err != nil {
			status["ml_service_error"] = err.Error()
		}
	} else {
		status["ml_service_available"] = false
		status["ml_service_enabled"] = false
	}

	return status
}

// Register creates a new user account
func (s *AuthService) Register(username, email, password string) (*models.User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	// Create user object
	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		IsActive:     true,
	}

	// Create user in database
	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	// Assign default 'user' role
	// Get role ID for 'user'
	// For simplicity, we're assuming it's ID 2 based on our seed data
	_ = s.userRepo.AssignRole(user.ID, 2)

	return user, nil
}

// EnableMFA generates a new MFA secret for a user
func (s *AuthService) EnableMFA(userID int64) (string, string, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return "", "", fmt.Errorf("error getting user: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.mfaIssuer,
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", fmt.Errorf("error generating TOTP key: %w", err)
	}

	// Save secret
	user.MFASecret = key.Secret()
	user.MFAEnabled = false // Not enabled until verified

	if err := s.userRepo.Update(user); err != nil {
		return "", "", fmt.Errorf("error updating user: %w", err)
	}

	// Return secret and URL for QR code
	return key.Secret(), key.URL(), nil
}

// VerifyMFA verifies the MFA code and enables MFA for the user
func (s *AuthService) VerifyMFA(userID int64, code string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("error getting user: %w", err)
	}

	// Verify MFA code
	valid := totp.Validate(code, user.MFASecret)
	if !valid {
		return ErrInvalidMFACode
	}

	// Enable MFA
	user.MFAEnabled = true

	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("error updating user: %w", err)
	}

	return nil
}

// DisableMFA disables MFA for a user
func (s *AuthService) DisableMFA(userID int64, password string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("error getting user: %w", err)
	}

	// Verify password first
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	// Disable MFA
	user.MFAEnabled = false
	user.MFASecret = ""

	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("error updating user: %w", err)
	}

	return nil
}

// VerifyToken validates a JWT token and returns the user ID
func (s *AuthService) VerifyToken(tokenString string) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.jwtSecret, nil
	})

	if err != nil {
		return 0, fmt.Errorf("error parsing token: %w", err)
	}

	// Validate token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check if token is expired
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return 0, errors.New("token expired")
			}
		}

		// Extract user ID
		if userID, ok := claims["sub"].(float64); ok {
			return int64(userID), nil
		}
	}

	return 0, errors.New("invalid token")
}

// HasPermission checks if a user has a specific permission
func (s *AuthService) HasPermission(userID int64, resource, action string) (bool, error) {
	return s.userRepo.HasPermission(userID, resource, action)
}

// generateToken generates a JWT token for a user
func (s *AuthService) generateToken(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":  user.ID,
		"name": user.Username,
		"exp":  time.Now().Add(s.jwtExpiration).Unix(),
		"iat":  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(s.jwtSecret)
}

// auditLoginAttempt logs a login attempt in the audit log
func (s *AuthService) auditLoginAttempt(userID int64, ipAddress, userAgent, status, details string) {
	auditLog := &models.AuditLog{
		UserID:    userID,
		EventType: "authentication",
		Resource:  "auth",
		Action:    "login",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Status:    status,
		Details:   details,
	}

	_ = s.auditRepo.CreateAuditLog(auditLog)
}

// timeOfDayInMinutes converts the current time to minutes from midnight
func timeOfDayInMinutes(t time.Time) int {
	return t.Hour()*60 + t.Minute()
}
