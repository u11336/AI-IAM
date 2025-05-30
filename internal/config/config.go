package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	Port                int     `json:"port"`
	DatabasePath        string  `json:"database_path"`
	JWTSecret           string  `json:"jwt_secret"`
	JWTExpirationHours  int     `json:"jwt_expiration_hours"`
	MFAEnabled          bool    `json:"mfa_enabled"`
	AnomalyDetectionOn  bool    `json:"anomaly_detection_on"`
	RiskThresholdLow    float64 `json:"risk_threshold_low"`
	RiskThresholdMedium float64 `json:"risk_threshold_medium"`
	RiskThresholdHigh   float64 `json:"risk_threshold_high"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	return &Config{
		Port:                8080,
		DatabasePath:        "./iam.db",
		JWTSecret:           "change-me-in-production", // In production, this should be loaded from a secure source
		JWTExpirationHours:  24,
		MFAEnabled:          true,
		AnomalyDetectionOn:  true,
		RiskThresholdLow:    0.3,
		RiskThresholdMedium: 0.6,
		RiskThresholdHigh:   0.9,
	}
}

// Load reads configuration from a file and environment variables
func Load() (*Config, error) {
	config := DefaultConfig()

	// Try to load from config file if it exists
	configPath := getConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		file, err := os.Open(configPath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		if err := decoder.Decode(config); err != nil {
			return nil, err
		}
	}

	// Override with environment variables if they exist
	if port := os.Getenv("IAM_PORT"); port != "" {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err == nil {
			config.Port = p
		}
	}

	if dbPath := os.Getenv("IAM_DB_PATH"); dbPath != "" {
		config.DatabasePath = dbPath
	}

	if secret := os.Getenv("IAM_JWT_SECRET"); secret != "" {
		config.JWTSecret = secret
	}

	return config, nil
}

// getConfigPath returns the path to the config file
func getConfigPath() string {
	if path := os.Getenv("IAM_CONFIG_PATH"); path != "" {
		return path
	}
	return filepath.Join(".", "config.json")
}
