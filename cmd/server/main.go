package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/u11336/ai-iam/internal/api"
	"github.com/u11336/ai-iam/internal/config"
	"github.com/u11336/ai-iam/internal/data/sqlite"
	"github.com/u11336/ai-iam/internal/utils"
)

func main() {
	// Initialize logger
	logger := utils.NewLogger()
	logger.Info("Starting AI-powered IAM system...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	// Initialize database
	db, err := sqlite.NewDB(cfg.DatabasePath)
	if err != nil {
		logger.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Initialize database schema
	if err := db.InitSchema(); err != nil {
		logger.Fatal("Failed to initialize database schema", "error", err)
	}

	// Setup API router - pass the underlying *sql.DB instead of *sqlite.DB
	router := api.NewRouter(db.DB, logger, cfg)

	// Start the server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: router,
	}

	// Start server in a goroutine so we can gracefully shut it down
	go func() {
		logger.Info("Server started", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	logger.Info("Server stopped")
}
