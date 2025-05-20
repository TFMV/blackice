package config

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// SetupLogging configures zerolog based on the provided logging configuration
func SetupLogging(cfg *LoggingConfig) error {
	// Set global log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	zerolog.SetGlobalLevel(level)

	// Set time format
	zerolog.TimeFieldFormat = time.RFC3339Nano

	// Configure log output
	var writers []io.Writer

	// Always include stderr for console output
	if cfg.Format == "console" {
		writers = append(writers, zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	} else {
		writers = append(writers, os.Stderr)
	}

	// Add file output if configured
	if cfg.File != "" {
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		writers = append(writers, file)
	}

	// Add any other output paths
	for _, path := range cfg.OutputPaths {
		if path == "stdout" {
			writers = append(writers, os.Stdout)
		} else if path == "stderr" {
			// Already added
			continue
		} else if path != cfg.File { // Don't add the file twice
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				return err
			}
			writers = append(writers, file)
		}
	}

	// Create multi-writer if we have multiple outputs
	var output io.Writer
	if len(writers) > 1 {
		output = zerolog.MultiLevelWriter(writers...)
	} else {
		output = writers[0]
	}

	// Set new global logger
	log.Logger = zerolog.New(output).With().Timestamp().Str("service", "flightgw").Logger()

	// Add trace ID if enabled
	if cfg.EnableTrace {
		log.Logger = log.With().Caller().Logger()
	}

	// Log configuration
	log.Info().
		Str("level", cfg.Level).
		Str("format", cfg.Format).
		Bool("json", cfg.EnableJSON).
		Bool("trace", cfg.EnableTrace).
		Str("file", cfg.File).
		Strs("output_paths", cfg.OutputPaths).
		Str("timestamp_format", cfg.TimestampFormat).
		Msg("Logging initialized")

	return nil
}
