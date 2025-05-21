package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"

	"github.com/TFMV/blackice/pkg/controlplane/config"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// AuditService provides audit logging capabilities for the Control Plane
type AuditService struct {
	config       *config.ControlPlaneConfig
	eventChannel chan *blackicev1.AuditLogEntry
	verifier     AttestationVerifier
	storage      AuditStorage
	wg           sync.WaitGroup
	shutdown     chan struct{}
}

// AttestationVerifier verifies attestations in audit logs
type AttestationVerifier interface {
	Verify(ctx context.Context, attestation *blackicev1.Attestation) (bool, error)
}

// AuditStorage defines the interface for audit log storage
type AuditStorage interface {
	Store(ctx context.Context, entry *blackicev1.AuditLogEntry) error
	Query(ctx context.Context, query *AuditQuery) ([]*blackicev1.AuditLogEntry, string, error)
	GetByID(ctx context.Context, id string) (*blackicev1.AuditLogEntry, error)
}

// FileAuditStorage implements audit storage using files
type FileAuditStorage struct {
	basePath string
	mutex    sync.RWMutex
}

// AuditQuery defines parameters for querying audit logs
type AuditQuery struct {
	StartTime  time.Time
	EndTime    time.Time
	UserIDs    []string
	Components []string
	Actions    []string
	Resources  []string
	PageSize   int
	PageToken  string
}

// NewAuditService creates a new audit service
func NewAuditService(cfg *config.ControlPlaneConfig, verifier AttestationVerifier) (*AuditService, error) {
	// Create storage provider
	var storage AuditStorage
	var err error

	if cfg.Audit.StoragePath != "" {
		storage, err = NewFileAuditStorage(cfg.Audit.StoragePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit storage: %w", err)
		}
	} else {
		// Use in-memory storage if no path is provided
		storage = NewMemoryAuditStorage(cfg.Audit.RetentionDays)
	}

	// Create audit service
	service := &AuditService{
		config:       cfg,
		eventChannel: make(chan *blackicev1.AuditLogEntry, 1000), // Buffer for 1000 events
		verifier:     verifier,
		storage:      storage,
		shutdown:     make(chan struct{}),
	}

	// Start worker goroutine
	service.wg.Add(1)
	go service.processEvents()

	return service, nil
}

// LogEvent asynchronously logs an audit event
func (s *AuditService) LogEvent(ctx context.Context, entry *blackicev1.AuditLogEntry) {
	// Skip logging if audit is disabled
	if !s.config.Audit.Enabled {
		return
	}

	// Set timestamp if not already set
	if entry.TimestampUnixNs == 0 {
		entry.TimestampUnixNs = time.Now().UnixNano()
	}

	// Generate ID if not already set
	if entry.Id == "" {
		entry.Id = uuid.New().String()
	}

	select {
	case s.eventChannel <- entry:
		// Successfully queued
	default:
		// Channel is full, log warning and proceed
		log.Warn().
			Str("event_id", entry.Id).
			Str("user_id", entry.UserId).
			Msg("Audit log channel full, dropping event")
	}
}

// LogEventSync synchronously logs an audit event
func (s *AuditService) LogEventSync(ctx context.Context, entry *blackicev1.AuditLogEntry) error {
	// Skip logging if audit is disabled
	if !s.config.Audit.Enabled {
		return nil
	}

	// Set timestamp if not already set
	if entry.TimestampUnixNs == 0 {
		entry.TimestampUnixNs = time.Now().UnixNano()
	}

	// Generate ID if not already set
	if entry.Id == "" {
		entry.Id = uuid.New().String()
	}

	// Verify attestation if required
	if s.config.Audit.VerifyAttestations && entry.Attestation != nil {
		verified, err := s.verifier.Verify(ctx, entry.Attestation)
		if err != nil {
			log.Warn().
				Str("event_id", entry.Id).
				Err(err).
				Msg("Failed to verify attestation for audit event")

			// Mark as unverified in the log but still store it
			if entry.Metadata == nil {
				entry.Metadata = make(map[string]string)
			}
			entry.Metadata["attestation_verified"] = "false"
			entry.Metadata["attestation_error"] = err.Error()
		} else if !verified {
			log.Warn().
				Str("event_id", entry.Id).
				Msg("Invalid attestation for audit event")

			if entry.Metadata == nil {
				entry.Metadata = make(map[string]string)
			}
			entry.Metadata["attestation_verified"] = "false"
		}
	}

	// Store the event
	return s.storage.Store(ctx, entry)
}

// GetAuditLogs retrieves audit logs based on query parameters
func (s *AuditService) GetAuditLogs(ctx context.Context, query *AuditQuery) ([]*blackicev1.AuditLogEntry, string, error) {
	return s.storage.Query(ctx, query)
}

// GetAuditLogByID retrieves a specific audit log by ID
func (s *AuditService) GetAuditLogByID(ctx context.Context, id string) (*blackicev1.AuditLogEntry, error) {
	return s.storage.GetByID(ctx, id)
}

// Shutdown stops the audit service
func (s *AuditService) Shutdown() {
	close(s.shutdown)
	s.wg.Wait()
}

// processEvents processes audit events from the channel
func (s *AuditService) processEvents() {
	defer s.wg.Done()

	for {
		select {
		case event := <-s.eventChannel:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := s.LogEventSync(ctx, event)
			if err != nil {
				log.Error().
					Err(err).
					Str("event_id", event.Id).
					Msg("Failed to store audit event")
			}
			cancel()

		case <-s.shutdown:
			// Drain any remaining events
			close(s.eventChannel)
			for event := range s.eventChannel {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := s.LogEventSync(ctx, event); err != nil {
					log.Error().
						Err(err).
						Str("event_id", event.Id).
						Msg("Failed to store audit event during shutdown")
				}
				cancel()
			}
			return
		}
	}
}

// NewFileAuditStorage creates a new file-based audit storage
func NewFileAuditStorage(basePath string) (*FileAuditStorage, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	return &FileAuditStorage{
		basePath: basePath,
	}, nil
}

// Store stores an audit log entry in a file
func (s *FileAuditStorage) Store(ctx context.Context, entry *blackicev1.AuditLogEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Create a file path based on the timestamp and ID
	timestamp := time.Unix(0, entry.TimestampUnixNs)
	datePath := filepath.Join(s.basePath, timestamp.Format("2006-01-02"))

	// Create the date directory if it doesn't exist
	if err := os.MkdirAll(datePath, 0755); err != nil {
		return fmt.Errorf("failed to create audit date directory: %w", err)
	}

	// Create the file
	filename := filepath.Join(datePath, fmt.Sprintf("%s.json", entry.Id))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create audit file: %w", err)
	}
	defer file.Close()

	// Write the entry as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	return nil
}

// Query retrieves audit logs based on query parameters
func (s *FileAuditStorage) Query(ctx context.Context, query *AuditQuery) ([]*blackicev1.AuditLogEntry, string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// This is a simplistic implementation for file-based storage
	// In a real implementation, this would use a more efficient indexing system

	var results []*blackicev1.AuditLogEntry

	// Calculate date range
	startDate := query.StartTime
	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, 0, -7) // Default to 1 week ago
	}

	endDate := query.EndTime
	if endDate.IsZero() {
		endDate = time.Now()
	}

	// Walk through date directories
	currentDate := startDate
	for !currentDate.After(endDate) {
		datePath := filepath.Join(s.basePath, currentDate.Format("2006-01-02"))

		// Check if directory exists
		_, err := os.Stat(datePath)
		if err == nil {
			// Directory exists, read files
			files, err := os.ReadDir(datePath)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read audit directory: %w", err)
			}

			// Process each file
			for _, file := range files {
				if filepath.Ext(file.Name()) != ".json" {
					continue
				}

				filePath := filepath.Join(datePath, file.Name())
				entry, err := s.readAuditFile(filePath)
				if err != nil {
					log.Warn().
						Str("file", filePath).
						Err(err).
						Msg("Failed to read audit file")
					continue
				}

				// Apply filters
				if s.matchesQuery(entry, query) {
					results = append(results, entry)
				}

				// Check if we have enough results
				if query.PageSize > 0 && len(results) >= query.PageSize {
					break
				}
			}
		}

		// Move to next day
		currentDate = currentDate.AddDate(0, 0, 1)
	}

	// Apply pagination
	var nextPageToken string
	if query.PageSize > 0 && len(results) > query.PageSize {
		nextPageToken = results[query.PageSize].Id
		results = results[:query.PageSize]
	}

	return results, nextPageToken, nil
}

// GetByID retrieves an audit log by its ID
func (s *FileAuditStorage) GetByID(ctx context.Context, id string) (*blackicev1.AuditLogEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// This is a naive implementation that searches all directories
	// A real implementation would use an index or a predictable path pattern

	// Read all date directories
	dirs, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit directories: %w", err)
	}

	// Search in each directory
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}

		// Check if the file exists in this directory
		filePath := filepath.Join(s.basePath, dir.Name(), fmt.Sprintf("%s.json", id))
		_, err := os.Stat(filePath)
		if err == nil {
			// File exists, read it
			return s.readAuditFile(filePath)
		}
	}

	return nil, fmt.Errorf("audit log not found: %s", id)
}

// readAuditFile reads an audit log from a file
func (s *FileAuditStorage) readAuditFile(filePath string) (*blackicev1.AuditLogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer file.Close()

	var entry blackicev1.AuditLogEntry
	if err := json.NewDecoder(file).Decode(&entry); err != nil {
		return nil, fmt.Errorf("failed to decode audit entry: %w", err)
	}

	return &entry, nil
}

// matchesQuery checks if an audit entry matches the query parameters
func (s *FileAuditStorage) matchesQuery(entry *blackicev1.AuditLogEntry, query *AuditQuery) bool {
	// Check timestamp
	timestamp := time.Unix(0, entry.TimestampUnixNs)
	if !query.StartTime.IsZero() && timestamp.Before(query.StartTime) {
		return false
	}
	if !query.EndTime.IsZero() && timestamp.After(query.EndTime) {
		return false
	}

	// Check user IDs
	if len(query.UserIDs) > 0 {
		found := false
		for _, userID := range query.UserIDs {
			if entry.UserId == userID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check components
	if len(query.Components) > 0 {
		found := false
		for _, component := range query.Components {
			if entry.ComponentId == component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check actions
	if len(query.Actions) > 0 {
		found := false
		for _, action := range query.Actions {
			if entry.Action == action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check resources
	if len(query.Resources) > 0 {
		found := false
		for _, resource := range query.Resources {
			if entry.Resource == resource {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// MemoryAuditStorage implements in-memory audit storage
type MemoryAuditStorage struct {
	entries       []*blackicev1.AuditLogEntry
	mutex         sync.RWMutex
	retentionDays int
}

// NewMemoryAuditStorage creates a new memory-based audit storage
func NewMemoryAuditStorage(retentionDays int) *MemoryAuditStorage {
	storage := &MemoryAuditStorage{
		entries:       make([]*blackicev1.AuditLogEntry, 0),
		retentionDays: retentionDays,
	}

	// Start background retention job
	go storage.startRetentionJob()

	return storage
}

// Store stores an audit log entry in memory
func (s *MemoryAuditStorage) Store(ctx context.Context, entry *blackicev1.AuditLogEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Make a deep copy of the entry to prevent external modifications
	// Using proto.Clone to properly copy protobuf messages with locks
	entryCopy := proto.Clone(entry).(*blackicev1.AuditLogEntry)

	// Add to the in-memory store
	s.entries = append(s.entries, entryCopy)

	return nil
}

// Query retrieves audit logs based on query parameters
func (s *MemoryAuditStorage) Query(ctx context.Context, query *AuditQuery) ([]*blackicev1.AuditLogEntry, string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Filter entries based on query
	var filtered []*blackicev1.AuditLogEntry

	for _, entry := range s.entries {
		if s.matchesQuery(entry, query) {
			filtered = append(filtered, entry)
		}
	}

	// Sort by timestamp (in a real implementation)
	// sort.Slice(filtered, func(i, j int) bool {
	//     return filtered[i].Timestamp > filtered[j].Timestamp // Descending
	// })

	// Apply pagination
	var nextPageToken string
	if query.PageSize > 0 && len(filtered) > query.PageSize {
		nextPageToken = filtered[query.PageSize].Id
		filtered = filtered[:query.PageSize]
	}

	return filtered, nextPageToken, nil
}

// GetByID retrieves an audit log by its ID
func (s *MemoryAuditStorage) GetByID(ctx context.Context, id string) (*blackicev1.AuditLogEntry, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, entry := range s.entries {
		if entry.Id == id {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("audit log not found: %s", id)
}

// matchesQuery checks if an audit entry matches the query parameters
func (s *MemoryAuditStorage) matchesQuery(entry *blackicev1.AuditLogEntry, query *AuditQuery) bool {
	// Check timestamp
	timestamp := time.Unix(0, entry.TimestampUnixNs)
	if !query.StartTime.IsZero() && timestamp.Before(query.StartTime) {
		return false
	}
	if !query.EndTime.IsZero() && timestamp.After(query.EndTime) {
		return false
	}

	// Check user IDs
	if len(query.UserIDs) > 0 {
		found := false
		for _, userID := range query.UserIDs {
			if entry.UserId == userID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check components
	if len(query.Components) > 0 {
		found := false
		for _, component := range query.Components {
			if entry.ComponentId == component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check actions
	if len(query.Actions) > 0 {
		found := false
		for _, action := range query.Actions {
			if entry.Action == action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check resources
	if len(query.Resources) > 0 {
		found := false
		for _, resource := range query.Resources {
			if entry.Resource == resource {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// startRetentionJob starts a background job to remove old entries
func (s *MemoryAuditStorage) startRetentionJob() {
	ticker := time.NewTicker(24 * time.Hour) // Run once a day
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupOldEntries()
	}
}

// cleanupOldEntries removes entries older than the retention period
func (s *MemoryAuditStorage) cleanupOldEntries() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.retentionDays <= 0 {
		return // Unlimited retention
	}

	cutoff := time.Now().AddDate(0, 0, -s.retentionDays).UnixNano()
	filtered := make([]*blackicev1.AuditLogEntry, 0, len(s.entries))

	for _, entry := range s.entries {
		if entry.TimestampUnixNs >= cutoff {
			filtered = append(filtered, entry)
		}
	}

	s.entries = filtered
}

// HashRequest creates a SHA-256 hash of request data for audit logs
func HashRequest(data interface{}) []byte {
	if data == nil {
		return []byte{}
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to hash request data for audit log")
		return []byte{}
	}

	hash := sha256.Sum256(jsonData)
	return hash[:]
}
