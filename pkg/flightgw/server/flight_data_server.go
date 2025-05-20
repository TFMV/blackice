// Package server provides core server functionality for the BlackIce Flight Gateway
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/flightgw/crypto"
)

// FlightDataServer implements an Arrow Flight server for storing and retrieving Arrow RecordBatches
// with advanced security, caching, and reliability features.
type FlightDataServer struct {
	flight.BaseFlightServer

	// Core server components
	server      *grpc.Server
	listener    net.Listener
	addr        string
	initialized bool

	// Security components
	hmacVerifier   *crypto.HMACVerifier
	merkleVerifier *crypto.MerkleVerifier
	tlsConfig      *tls.Config

	// Data storage
	batchesMu   sync.RWMutex
	batches     map[string]arrow.Record
	expirations map[string]time.Time
	ttl         time.Duration

	// Memory management
	allocator memory.Allocator

	// Background task management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics and monitoring
	metrics *ServerMetrics

	// Circuit breaker for handling overload scenarios
	circuitBreaker *CircuitBreaker
}

// ServerMetrics tracks operational metrics for the server
type ServerMetrics struct {
	mu                 sync.RWMutex
	startTime          time.Time
	getBatchCount      int64
	putBatchCount      int64
	currentBatches     int
	totalMemoryBytes   int64
	lastGCTime         time.Time
	batchSizeHistogram map[int]int // Maps size ranges to counts
}

// FlightDataServerConfig contains configuration options for the Flight data server
type FlightDataServerConfig struct {
	// Address to listen on (e.g., "localhost:8080")
	Addr string

	// Memory allocator to use
	Allocator memory.Allocator

	// TTL for stored batches (default: 1 hour)
	TTL time.Duration

	// Security configuration
	TLSConfig          *tls.Config
	EnableHMAC         bool
	HMACSecretPath     string
	EnableMerkleVerify bool

	// Circuit breaker configuration
	CircuitBreakerConfig map[string]interface{}

	// Memory management
	MaxMemoryBytes int64
	EnableGC       bool
	GCInterval     time.Duration
}

// NewFlightDataServer creates a new Arrow Flight data server
func NewFlightDataServer(config FlightDataServerConfig) (*FlightDataServer, error) {
	if config.Addr == "" {
		config.Addr = "localhost:8080"
	}
	if config.Allocator == nil {
		config.Allocator = memory.NewGoAllocator()
	}
	if config.TTL == 0 {
		config.TTL = 1 * time.Hour
	}
	if config.GCInterval == 0 {
		config.GCInterval = 5 * time.Minute
	}
	if config.MaxMemoryBytes == 0 {
		config.MaxMemoryBytes = 1 * 1024 * 1024 * 1024 // 1GB default
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &FlightDataServer{
		addr:        config.Addr,
		batches:     make(map[string]arrow.Record),
		expirations: make(map[string]time.Time),
		allocator:   config.Allocator,
		ttl:         config.TTL,
		tlsConfig:   config.TLSConfig,
		ctx:         ctx,
		cancel:      cancel,
		metrics: &ServerMetrics{
			startTime:          time.Now(),
			lastGCTime:         time.Now(),
			batchSizeHistogram: make(map[int]int),
		},
		circuitBreaker: NewMilitaryGradeCircuitBreaker(config.CircuitBreakerConfig),
	}

	// Initialize HMAC verifier if enabled
	if config.EnableHMAC {
		var err error
		server.hmacVerifier, err = crypto.NewHMACVerifier(
			"sha256", // Default to SHA-256
			config.HMACSecretPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HMAC verifier: %w", err)
		}
		log.Info().Msg("HMAC verification enabled")
	}

	// Initialize Merkle verifier if enabled
	if config.EnableMerkleVerify {
		var err error
		server.merkleVerifier, err = crypto.NewMerkleVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Merkle verifier: %w", err)
		}
		log.Info().Msg("Merkle verification enabled")
	}

	// Set up the gRPC server with appropriate options
	var grpcOpts []grpc.ServerOption

	// Configure TLS if provided
	if config.TLSConfig != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(config.TLSConfig)))
		log.Info().Msg("TLS encryption enabled")
	} else {
		grpcOpts = append(grpcOpts, grpc.Creds(insecure.NewCredentials()))
		log.Warn().Msg("TLS not configured, using insecure connection")
	}

	// Configure message size limits
	grpcOpts = append(grpcOpts,
		grpc.MaxRecvMsgSize(256*1024*1024), // 256MB max message size
		grpc.MaxSendMsgSize(256*1024*1024), // 256MB max message size
	)

	// Create the gRPC server
	server.server = grpc.NewServer(grpcOpts...)

	// Register the Flight service
	flight.RegisterFlightServiceServer(server.server, server)

	// Start background tasks
	if config.EnableGC {
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			server.cleanupExpiredBatches(ctx, config.GCInterval)
		}()
		log.Info().Dur("interval", config.GCInterval).Msg("Started background cleanup process")
	}

	server.initialized = true
	log.Info().Str("addr", config.Addr).Msg("Flight data server initialized")

	return server, nil
}

// Start starts the Flight server
func (s *FlightDataServer) Start() error {
	if !s.initialized {
		return fmt.Errorf("server not initialized")
	}

	log.Info().Str("addr", s.addr).Msg("Starting Flight data server")

	// Create a listener
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}
	s.listener = lis

	// Start the server in a goroutine
	go func() {
		if err := s.server.Serve(lis); err != nil {
			log.Error().Err(err).Msg("Flight data server stopped with error")
		}
	}()

	log.Info().Str("addr", s.addr).Msg("Flight data server started successfully")
	return nil
}

// Stop stops the Flight server and waits for all background tasks to complete
func (s *FlightDataServer) Stop() {
	log.Info().Msg("Stopping Flight data server")

	// Cancel the context to signal all background tasks to stop
	if s.cancel != nil {
		s.cancel()
	}

	// Wait for all background tasks to complete with a timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Debug().Msg("All background tasks completed")
	case <-time.After(10 * time.Second):
		log.Warn().Msg("Timed out waiting for background tasks to complete")
	}

	// Clear all batches to release memory
	s.batchesMu.Lock()
	for id, batch := range s.batches {
		batch.Release()
		delete(s.batches, id)
		delete(s.expirations, id)
	}
	s.batchesMu.Unlock()

	// Stop the gRPC server gracefully
	if s.server != nil {
		s.server.GracefulStop()
	}

	// Close the listener if it exists
	if s.listener != nil {
		s.listener.Close()
	}

	log.Info().Msg("Flight data server stopped")
}

// GetFlightInfo implements the Flight GetFlightInfo method
func (s *FlightDataServer) GetFlightInfo(ctx context.Context, request *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	log.Debug().Str("descriptor_type", fmt.Sprintf("%v", request.Type)).Msg("GetFlightInfo request received")

	if err := s.verifyCircuitBreaker(); err != nil {
		return nil, status.Errorf(codes.ResourceExhausted, "server overloaded: %v", err)
	}

	// Verify the request if HMAC is enabled
	if s.hmacVerifier != nil {
		// Extract metadata from context
		md, ok := getMetadataFromContext(ctx)
		if !ok {
			log.Warn().Msg("Missing metadata for HMAC verification")
		} else {
			// Get the HMAC signature from metadata
			hmacSignature := md["x-blackice-hmac"]
			if hmacSignature == "" {
				log.Warn().Msg("Missing HMAC signature in request")
			} else {
				// Create message to verify based on descriptor type
				var message []byte
				switch request.Type {
				case flight.DescriptorPATH:
					// Convert []string to string for path
					pathStr := strings.Join(request.Path, "/")
					message = []byte(fmt.Sprintf("PATH:%s", pathStr))
				case flight.DescriptorCMD:
					message = []byte(fmt.Sprintf("CMD:%s", string(request.Cmd)))
				default:
					return nil, status.Errorf(codes.InvalidArgument, "unsupported descriptor type")
				}

				// Verify HMAC
				valid, err := s.hmacVerifier.VerifyHMACHex(hmacSignature, message)
				if err != nil {
					log.Error().Err(err).Msg("HMAC verification error")
					return nil, status.Errorf(codes.Internal, "HMAC verification error: %v", err)
				}

				if !valid {
					log.Warn().Str("hmac", hmacSignature).Msg("Invalid HMAC signature")
					return nil, status.Errorf(codes.Unauthenticated, "invalid HMAC signature")
				}

				log.Debug().Msg("HMAC verification successful")
			}
		}
	}

	cmd := string(request.Cmd)

	s.batchesMu.RLock()
	batch, ok := s.batches[cmd]
	s.batchesMu.RUnlock()

	if !ok {
		return nil, status.Errorf(codes.NotFound, "batch with ID %s not found", cmd)
	}

	endpoint := &flight.FlightEndpoint{
		Ticket: &flight.Ticket{Ticket: []byte(cmd)},
		Location: []*flight.Location{
			{Uri: fmt.Sprintf("grpc://%s", s.addr)},
		},
	}

	schemaBytes := flight.SerializeSchema(batch.Schema(), s.allocator)

	// Estimate the total bytes
	var totalBytes int64
	for i := 0; i < int(batch.NumCols()); i++ {
		if arr := batch.Column(i); arr != nil && arr.Data() != nil {
			totalBytes += int64(arr.Data().Buffers()[1].Len())
		}
	}

	return &flight.FlightInfo{
		Schema:           schemaBytes,
		FlightDescriptor: request,
		Endpoint:         []*flight.FlightEndpoint{endpoint},
		TotalRecords:     batch.NumRows(),
		TotalBytes:       totalBytes,
	}, nil
}

// DoGet implements the Flight DoGet method
func (s *FlightDataServer) DoGet(request *flight.Ticket, stream flight.FlightService_DoGetServer) error {
	batchID := string(request.Ticket)
	log.Debug().Str("batch_id", batchID).Msg("DoGet request received")

	if err := s.verifyCircuitBreaker(); err != nil {
		return status.Errorf(codes.ResourceExhausted, "server overloaded: %v", err)
	}

	// Verify the request if HMAC is enabled
	if s.hmacVerifier != nil {
		// Extract HMAC signature from ticket
		// Expected format: batchID|hmacSignature
		parts := strings.Split(batchID, "|")
		if len(parts) != 2 {
			log.Warn().Str("batch_id", batchID).Msg("Invalid ticket format for HMAC verification")
		} else {
			actualBatchID := parts[0]
			hmacSignature := parts[1]

			// Verify HMAC
			valid, err := s.hmacVerifier.VerifyHMACHex(hmacSignature, []byte(actualBatchID))
			if err != nil {
				log.Error().Err(err).Msg("HMAC verification error")
				return status.Errorf(codes.Internal, "HMAC verification error: %v", err)
			}

			if !valid {
				log.Warn().Str("hmac", hmacSignature).Msg("Invalid HMAC signature")
				return status.Errorf(codes.Unauthenticated, "invalid HMAC signature")
			}

			// Update batchID to use the actual ID without the signature
			batchID = actualBatchID
			log.Debug().Msg("HMAC verification successful")
		}
	}

	s.batchesMu.Lock()
	batch, ok := s.batches[batchID]
	if ok {
		// Update the expiration time
		s.expirations[batchID] = time.Now().Add(s.ttl)
	}
	s.batchesMu.Unlock()

	if !ok {
		return status.Errorf(codes.NotFound, "batch with ID %s not found", batchID)
	}

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.getBatchCount++
	s.metrics.mu.Unlock()

	// Create a writer for the stream
	writer := flight.NewRecordWriter(stream, ipc.WithSchema(batch.Schema()))
	defer writer.Close()

	// Write the batch to the stream and handle errors
	err := s.executeWithCircuitBreaker(func() error {
		return writer.Write(batch)
	})

	if err != nil {
		log.Error().Err(err).Str("batch_id", batchID).Msg("Failed to write batch to stream")
		return status.Errorf(codes.Internal, "failed to write batch to stream: %v", err)
	}

	return nil
}

// DoPut implements the Flight DoPut method
func (s *FlightDataServer) DoPut(stream flight.FlightService_DoPutServer) error {
	log.Debug().Msg("DoPut request received")

	if err := s.verifyCircuitBreaker(); err != nil {
		return status.Errorf(codes.ResourceExhausted, "server overloaded: %v", err)
	}

	// Get the first message which should contain the descriptor
	firstMsg, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to receive descriptor: %v", err)
	}

	// Check if we have a descriptor
	if firstMsg.FlightDescriptor == nil {
		return status.Errorf(codes.InvalidArgument, "missing flight descriptor in first message")
	}

	// Verify the descriptor if HMAC is enabled
	if s.hmacVerifier != nil {
		// Extract metadata from context
		ctx := stream.Context()
		md, ok := getMetadataFromContext(ctx)
		if !ok {
			log.Warn().Msg("Missing metadata for HMAC verification")
		} else {
			// Get the HMAC signature from metadata
			hmacSignature := md["x-blackice-descriptor-hmac"]
			if hmacSignature == "" {
				log.Warn().Msg("Missing HMAC signature in request")
			} else {
				// Create message to verify based on descriptor type
				var message []byte
				switch firstMsg.FlightDescriptor.Type {
				case flight.DescriptorPATH:
					// Convert []string to string for path
					pathStr := strings.Join(firstMsg.FlightDescriptor.Path, "/")
					message = []byte(fmt.Sprintf("PATH:%s", pathStr))
				case flight.DescriptorCMD:
					message = []byte(fmt.Sprintf("CMD:%s", string(firstMsg.FlightDescriptor.Cmd)))
				default:
					return status.Errorf(codes.InvalidArgument, "unsupported descriptor type")
				}

				// Verify HMAC
				valid, err := s.hmacVerifier.VerifyHMACHex(hmacSignature, message)
				if err != nil {
					log.Error().Err(err).Msg("HMAC verification error")
					return status.Errorf(codes.Internal, "HMAC verification error: %v", err)
				}

				if !valid {
					log.Warn().Str("hmac", hmacSignature).Msg("Invalid HMAC signature")
					return status.Errorf(codes.Unauthenticated, "invalid HMAC signature")
				}

				log.Debug().Msg("HMAC verification successful")
			}
		}
	}

	// Create a reader for the stream
	reader, err := flight.NewRecordReader(stream)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create record reader: %v", err)
	}
	defer reader.Release()

	// Read the first record
	if !reader.Next() {
		if err := reader.Err(); err != nil {
			return status.Errorf(codes.Internal, "error reading record: %v", err)
		}
		return status.Errorf(codes.InvalidArgument, "no record received")
	}

	// Get the record and retain it
	batch := reader.Record()
	batch.Retain() // Retain the batch so it's not released when the reader is released

	// Check if the batch is too large
	batchSizeBytes := estimateBatchSize(batch)

	// Update metrics for the batch size histogram
	s.updateBatchSizeHistogram(batchSizeBytes)

	// Check circuit breaker status after receiving data (memory pressure might have increased)
	if err := s.verifyCircuitBreaker(); err != nil {
		batch.Release() // Release the batch since we're not using it
		return status.Errorf(codes.ResourceExhausted, "server overloaded after receiving data: %v", err)
	}

	// Generate a unique ID for the batch
	batchID := generateBatchID()

	// Calculate the merkle root if enabled
	if s.merkleVerifier != nil {
		// Calculate Merkle root for the batch data
		merkleRoot, err := calculateMerkleRoot(batch)
		if err != nil {
			log.Error().Err(err).Msg("Failed to calculate Merkle root")
		} else {
			// Store Merkle root in metadata
			// In a production system, this would be stored in a persistent store
			log.Debug().Str("merkle_root", merkleRoot).Str("batch_id", batchID).Msg("Calculated Merkle root")
		}
	}

	// Store the batch
	defer func() {
		// If we return with an error, make sure to release the batch
		if err != nil && batch != nil {
			batch.Release()
			batch = nil
		}
	}()

	err = s.executeWithCircuitBreaker(func() error {
		s.batchesMu.Lock()
		defer s.batchesMu.Unlock()

		// Check memory usage before adding the batch
		if s.metrics.totalMemoryBytes+batchSizeBytes > s.getCurrentMemoryLimit() {
			return status.Errorf(codes.ResourceExhausted, "memory limit exceeded")
		}

		s.batches[batchID] = batch
		s.expirations[batchID] = time.Now().Add(s.ttl)

		// Update metrics
		s.metrics.mu.Lock()
		s.metrics.putBatchCount++
		s.metrics.currentBatches = len(s.batches)
		s.metrics.totalMemoryBytes += batchSizeBytes
		s.metrics.mu.Unlock()

		return nil
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to store batch")
		return err
	}

	// We've successfully stored the batch, so don't release it on exit
	batch = nil

	// Send the batch ID back to the client
	err = stream.Send(&flight.PutResult{
		AppMetadata: []byte(batchID),
	})

	if err != nil {
		// If we fail to send the result, remove the batch from storage
		s.batchesMu.Lock()
		if storedBatch, ok := s.batches[batchID]; ok {
			storedBatch.Release()
			delete(s.batches, batchID)
			delete(s.expirations, batchID)

			// Update metrics
			s.metrics.mu.Lock()
			s.metrics.currentBatches = len(s.batches)
			s.metrics.totalMemoryBytes -= batchSizeBytes
			s.metrics.mu.Unlock()
		}
		s.batchesMu.Unlock()

		return status.Errorf(codes.Internal, "failed to send result: %v", err)
	}

	log.Debug().Str("batch_id", batchID).Int64("size_bytes", batchSizeBytes).Int64("rows", batch.NumRows()).Msg("Batch stored successfully")

	return nil
}

// ListFlights implements the Flight ListFlights method
func (s *FlightDataServer) ListFlights(request *flight.Criteria, stream flight.FlightService_ListFlightsServer) error {
	log.Debug().Msg("ListFlights request received")

	if err := s.verifyCircuitBreaker(); err != nil {
		return status.Errorf(codes.ResourceExhausted, "server overloaded: %v", err)
	}

	s.batchesMu.RLock()
	defer s.batchesMu.RUnlock()

	for batchID, batch := range s.batches {
		descriptor := &flight.FlightDescriptor{
			Type: flight.DescriptorCMD,
			Cmd:  []byte(batchID),
		}

		endpoint := &flight.FlightEndpoint{
			Ticket: &flight.Ticket{Ticket: []byte(batchID)},
			Location: []*flight.Location{
				{Uri: fmt.Sprintf("grpc://%s", s.addr)},
			},
		}

		// Get the expiration time
		expiration, ok := s.expirations[batchID]

		// Calculate time until expiration
		var timeToLive int64
		if ok {
			timeToLive = expiration.Unix() - time.Now().Unix()
			if timeToLive < 0 {
				timeToLive = 0
			}
		}

		schemaBytes := flight.SerializeSchema(batch.Schema(), s.allocator)

		// Estimate the total bytes
		var totalBytes int64
		for i := 0; i < int(batch.NumCols()); i++ {
			if arr := batch.Column(i); arr != nil && arr.Data() != nil {
				totalBytes += int64(arr.Data().Buffers()[1].Len())
			}
		}

		info := &flight.FlightInfo{
			Schema:           schemaBytes,
			FlightDescriptor: descriptor,
			Endpoint:         []*flight.FlightEndpoint{endpoint},
			TotalRecords:     batch.NumRows(),
			TotalBytes:       totalBytes,
			// Store TTL in app metadata as base64 JSON
			AppMetadata: []byte(fmt.Sprintf(`{"ttl":%d}`, timeToLive)),
		}

		if err := stream.Send(info); err != nil {
			return status.Errorf(codes.Internal, "failed to send flight info: %v", err)
		}
	}

	return nil
}

// DoAction implements the Flight DoAction method for custom operations
func (s *FlightDataServer) DoAction(action *flight.Action, stream flight.FlightService_DoActionServer) error {
	log.Debug().Str("action", action.Type).Msg("DoAction request received")

	switch action.Type {
	case "ping":
		// Simple ping action to check server health
		return stream.Send(&flight.Result{Body: []byte("pong")})

	case "stats":
		// Return server statistics
		stats := s.getStats()
		return stream.Send(&flight.Result{Body: []byte(stats)})

	case "delete_batch":
		// Delete a specific batch
		batchID := string(action.Body)
		if err := s.deleteBatch(batchID); err != nil {
			return status.Errorf(codes.Internal, "failed to delete batch: %v", err)
		}
		return stream.Send(&flight.Result{Body: []byte("deleted")})

	case "gc":
		// Trigger garbage collection
		count := s.performCleanup()
		return stream.Send(&flight.Result{Body: []byte(fmt.Sprintf("cleaned %d batches", count))})

	default:
		return status.Errorf(codes.Unimplemented, "action type %s not implemented", action.Type)
	}
}

// cleanupExpiredBatches periodically removes expired batches
func (s *FlightDataServer) cleanupExpiredBatches(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			count := s.performCleanup()
			if count > 0 {
				log.Info().Int("count", count).Msg("Cleaned up expired batches")
			}
		case <-ctx.Done():
			log.Debug().Msg("Stopping batch cleanup routine")
			return
		}
	}
}

// performCleanup handles the actual cleanup of expired batches
// Returns the number of batches cleaned up
func (s *FlightDataServer) performCleanup() int {
	now := time.Now()
	var expiredIDs []string
	var freedBytes int64

	// Find expired batches
	s.batchesMu.RLock()
	for batchID, expiration := range s.expirations {
		if now.After(expiration) {
			expiredIDs = append(expiredIDs, batchID)
		}
	}
	s.batchesMu.RUnlock()

	// Remove expired batches
	if len(expiredIDs) > 0 {
		s.batchesMu.Lock()
		for _, batchID := range expiredIDs {
			if batch, ok := s.batches[batchID]; ok {
				batchSize := estimateBatchSize(batch)
				freedBytes += batchSize

				batch.Release()
				delete(s.batches, batchID)
				delete(s.expirations, batchID)
			}
		}

		// Update metrics
		s.metrics.mu.Lock()
		s.metrics.currentBatches = len(s.batches)
		s.metrics.totalMemoryBytes -= freedBytes
		s.metrics.lastGCTime = time.Now()
		s.metrics.mu.Unlock()

		s.batchesMu.Unlock()
	}

	return len(expiredIDs)
}

// deleteBatch deletes a batch by ID
func (s *FlightDataServer) deleteBatch(batchID string) error {
	s.batchesMu.Lock()
	defer s.batchesMu.Unlock()

	batch, ok := s.batches[batchID]
	if !ok {
		return status.Errorf(codes.NotFound, "batch with ID %s not found", batchID)
	}

	batchSize := estimateBatchSize(batch)

	batch.Release()
	delete(s.batches, batchID)
	delete(s.expirations, batchID)

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.currentBatches = len(s.batches)
	s.metrics.totalMemoryBytes -= batchSize
	s.metrics.mu.Unlock()

	log.Debug().Str("batch_id", batchID).Msg("Batch deleted")

	return nil
}

// estimateBatchSize estimates the memory size of an Arrow Record
func estimateBatchSize(batch arrow.Record) int64 {
	if batch == nil {
		return 0
	}

	var totalBytes int64

	// Calculate schema size
	schemaSize := int64(batch.Schema().NumFields() * 50) // Rough estimate for schema overhead

	// Sum up the size of each column's data
	for i := 0; i < int(batch.NumCols()); i++ {
		col := batch.Column(i)
		if col == nil || col.Data() == nil {
			continue
		}

		// For each buffer in the column
		for _, buffer := range col.Data().Buffers() {
			if buffer != nil {
				totalBytes += int64(buffer.Len())
			}
		}
	}

	// Add schema size and some overhead for the record structure
	return totalBytes + schemaSize + 1024
}

// getCurrentMemoryLimit returns the current memory limit which may change based on system conditions
func (s *FlightDataServer) getCurrentMemoryLimit() int64 {
	// This could be enhanced to dynamically adjust based on system load
	return 1 * 1024 * 1024 * 1024 // 1GB default
}

// generateBatchID generates a unique batch ID
func generateBatchID() string {
	return fmt.Sprintf("batch-%s", uuid.New().String())
}

// getStats returns a JSON string of server statistics
func (s *FlightDataServer) getStats() string {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	uptime := time.Since(s.metrics.startTime).String()

	s.batchesMu.RLock()
	batchCount := len(s.batches)
	s.batchesMu.RUnlock()

	circuitBreakerState := s.circuitBreaker.GetState()

	stats := fmt.Sprintf(`{
		"uptime": "%s",
		"batches": {
			"current": %d,
			"get_operations": %d,
			"put_operations": %d
		},
		"memory": {
			"used_bytes": %d,
			"last_gc": "%s"
		},
		"circuit_breaker": "%v"
	}`, uptime, batchCount, s.metrics.getBatchCount, s.metrics.putBatchCount,
		s.metrics.totalMemoryBytes, s.metrics.lastGCTime.Format(time.RFC3339),
		circuitBreakerState)

	return stats
}

// updateBatchSizeHistogram updates the histogram of batch sizes for metrics
func (s *FlightDataServer) updateBatchSizeHistogram(sizeBytes int64) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	// Categorize by size (in KB)
	sizeKB := int(sizeBytes / 1024)

	var category int
	switch {
	case sizeKB < 10:
		category = 10
	case sizeKB < 100:
		category = 100
	case sizeKB < 1000:
		category = 1000
	case sizeKB < 10000:
		category = 10000
	default:
		category = 100000 // 100MB+
	}

	s.metrics.batchSizeHistogram[category]++
}

// verifyCircuitBreaker checks if the circuit breaker is open
func (s *FlightDataServer) verifyCircuitBreaker() error {
	if s.circuitBreaker.GetState() == CircuitOpen {
		return fmt.Errorf("circuit breaker is open")
	}
	return nil
}

// executeWithCircuitBreaker executes a function with the circuit breaker
func (s *FlightDataServer) executeWithCircuitBreaker(fn func() error) error {
	return s.circuitBreaker.Execute(fn)
}

// StoreBatch stores an Arrow Record batch with the given ID
// This provides a simpler interface to store batches directly without using DoGet/DoPut
func (s *FlightDataServer) StoreBatch(batchID string, batch arrow.Record) error {
	s.batchesMu.Lock()
	defer s.batchesMu.Unlock()

	// Safety check
	if batch == nil {
		return fmt.Errorf("cannot store nil batch")
	}

	// Retain the batch to ensure it's not released while we hold it
	batch.Retain()

	// Calculate the batch size
	batchSizeBytes := estimateBatchSize(batch)

	// Check memory usage before adding the batch
	if s.metrics.totalMemoryBytes+batchSizeBytes > s.getCurrentMemoryLimit() {
		// Release the batch since we're not storing it
		batch.Release()
		return status.Errorf(codes.ResourceExhausted, "memory limit exceeded")
	}

	// Store the batch
	s.batches[batchID] = batch
	s.expirations[batchID] = time.Now().Add(s.ttl)

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.putBatchCount++
	s.metrics.currentBatches = len(s.batches)
	s.metrics.totalMemoryBytes += batchSizeBytes
	s.metrics.mu.Unlock()

	log.Debug().Str("batch_id", batchID).Int64("size_bytes", batchSizeBytes).Int64("rows", batch.NumRows()).Msg("Batch stored successfully")

	return nil
}

// GetBatch retrieves an Arrow Record batch by ID
// This provides a simpler interface to retrieve batches directly without using DoGet/DoPut
func (s *FlightDataServer) GetBatch(batchID string) (arrow.Record, error) {
	s.batchesMu.Lock()
	defer s.batchesMu.Unlock()

	batch, ok := s.batches[batchID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "batch with ID %s not found", batchID)
	}

	// Update the expiration time
	s.expirations[batchID] = time.Now().Add(s.ttl)

	// Update metrics
	s.metrics.mu.Lock()
	s.metrics.getBatchCount++
	s.metrics.mu.Unlock()

	// Retain the batch to ensure it's not released while the caller is using it
	batch.Retain()

	log.Debug().Str("batch_id", batchID).Int64("rows", batch.NumRows()).Msg("Batch retrieved successfully")

	return batch, nil
}

// getMetadataFromContext extracts metadata from a gRPC context
func getMetadataFromContext(ctx context.Context) (map[string]string, bool) {
	md := make(map[string]string)

	// Get metadata from gRPC context
	grpcMD, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return md, false
	}

	// Convert to string map
	for key, values := range grpcMD {
		if len(values) > 0 {
			md[key] = values[0]
		}
	}

	return md, true
}

// calculateMerkleRoot calculates a Merkle root hash for the record batch
func calculateMerkleRoot(batch arrow.Record) (string, error) {
	// Create a hash for each column
	columnHashes := make([][]byte, batch.NumCols())

	for i := 0; i < int(batch.NumCols()); i++ {
		col := batch.Column(i)
		if col == nil || col.Data() == nil {
			continue
		}

		// Create SHA-256 hash of column data
		h := sha256.New()

		// Add column name to hash
		field := batch.Schema().Field(i)
		h.Write([]byte(field.Name))

		// Hash each buffer in the column
		for _, buffer := range col.Data().Buffers() {
			if buffer != nil && buffer.Len() > 0 {
				h.Write(buffer.Bytes())
			}
		}

		columnHashes[i] = h.Sum(nil)
	}

	// Create Merkle tree from column hashes
	return calculateMerkleTreeRoot(columnHashes), nil
}

// calculateMerkleTreeRoot calculates a Merkle root from a list of hashes
func calculateMerkleTreeRoot(hashes [][]byte) string {
	if len(hashes) == 0 {
		return ""
	}

	// If there's only one hash, that's the root
	if len(hashes) == 1 {
		return fmt.Sprintf("%x", hashes[0])
	}

	// Build the Merkle tree bottom-up
	for len(hashes) > 1 {
		// If odd number of hashes, duplicate the last one
		if len(hashes)%2 == 1 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		// Create the next level of the tree
		nextLevel := make([][]byte, 0, len(hashes)/2)

		// Combine pairs of hashes
		for i := 0; i < len(hashes); i += 2 {
			h := sha256.New()
			h.Write(hashes[i])
			h.Write(hashes[i+1])
			nextLevel = append(nextLevel, h.Sum(nil))
		}

		// Move up to the next level
		hashes = nextLevel
	}

	// Return the root as a hex string
	return fmt.Sprintf("%x", hashes[0])
}
