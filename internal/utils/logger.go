package utils

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

// Log levels
const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// Logger is a simple structured logger
type Logger struct {
	level      LogLevel
	logger     *log.Logger
	showCaller bool
}

// NewLogger creates a new logger with default settings
func NewLogger() *Logger {
	return &Logger{
		level:      INFO,
		logger:     log.New(os.Stdout, "", 0),
		showCaller: true,
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// SetShowCaller sets whether to show the caller information
func (l *Logger) SetShowCaller(show bool) {
	l.showCaller = show
}

// SetLogger sets the underlying logger (used for testing)
func (l *Logger) SetLogger(logger *log.Logger) {
	l.logger = logger
}

// formatMessage formats a log message with key-value pairs
func (l *Logger) formatMessage(level, message string, keyValues ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Get caller information if enabled
	var caller string
	if l.showCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			// Extract just the filename, not the full path
			parts := strings.Split(file, "/")
			file = parts[len(parts)-1]
			caller = fmt.Sprintf(" %s:%d", file, line)
		}
	}

	// Format the base message
	formattedMsg := fmt.Sprintf("[%s] %s%s: %s", timestamp, level, caller, message)

	// Add key-value pairs if provided
	if len(keyValues) > 0 {
		if len(keyValues)%2 != 0 {
			// If odd number of args, add an empty value to make it even
			keyValues = append(keyValues, "MISSING")
		}

		pairs := make([]string, 0, len(keyValues)/2)
		for i := 0; i < len(keyValues); i += 2 {
			key := fmt.Sprintf("%v", keyValues[i])
			value := fmt.Sprintf("%v", keyValues[i+1])
			pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
		}

		formattedMsg += " " + strings.Join(pairs, " ")
	}

	return formattedMsg
}

// Debug logs a debug message
func (l *Logger) Debug(message string, keyValues ...interface{}) {
	if l.level <= DEBUG {
		l.logger.Println(l.formatMessage("DEBUG", message, keyValues...))
	}
}

// Info logs an info message
func (l *Logger) Info(message string, keyValues ...interface{}) {
	if l.level <= INFO {
		l.logger.Println(l.formatMessage("INFO", message, keyValues...))
	}
}

// Warn logs a warning message
func (l *Logger) Warn(message string, keyValues ...interface{}) {
	if l.level <= WARN {
		l.logger.Println(l.formatMessage("WARN", message, keyValues...))
	}
}

// Error logs an error message
func (l *Logger) Error(message string, keyValues ...interface{}) {
	if l.level <= ERROR {
		l.logger.Println(l.formatMessage("ERROR", message, keyValues...))
	}
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(message string, keyValues ...interface{}) {
	if l.level <= FATAL {
		l.logger.Fatalln(l.formatMessage("FATAL", message, keyValues...))
	}
}
