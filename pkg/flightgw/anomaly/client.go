// Package anomaly provides anomaly detection and response capabilities for the BlackIce system.
package anomaly

import (
	"context"
	"fmt"
	"sync"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client provides a client for the anomaly detection service
type Client struct {
	conn        *grpc.ClientConn
	client      blackicev1.AnomalyServiceClient
	buffer      []*TelemetryEvent
	bufferMu    sync.Mutex
	bufferSize  int
	maxBuffer   int
	address     string
	connected   bool
	ctx         context.Context
	cancel      context.CancelFunc
	reconnectCh chan struct{}
	wg          sync.WaitGroup // Added for managing background goroutines
}

// ClientConfig contains the configuration for the anomaly client
type ClientConfig struct {
	ServiceAddress  string
	BufferSize      int
	FlushInterval   time.Duration
	ReconnectDelay  time.Duration
	TLSEnabled      bool
	RetentionPolicy RetentionPolicy
	// Added field for message size configuration
	MaxMessageSizeMB int
}

// RetentionPolicy defines how events are retained when the service is unavailable
type RetentionPolicy string

const (
	// DropOldest drops the oldest events when the buffer is full
	DropOldest RetentionPolicy = "drop_oldest"
	// DropNewest drops the newest events when the buffer is full
	DropNewest RetentionPolicy = "drop_newest"
	// DropAll drops all events when the buffer is full
	DropAll RetentionPolicy = "drop_all"

	// Default message size limit
	DefaultMaxMessageSizeMB = 64
)

// DefaultClientConfig returns a default configuration for the anomaly client
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServiceAddress:   "localhost:8089",
		BufferSize:       1000,
		FlushInterval:    5 * time.Second,
		ReconnectDelay:   5 * time.Second,
		TLSEnabled:       false,
		RetentionPolicy:  DropOldest,
		MaxMessageSizeMB: DefaultMaxMessageSizeMB,
	}
}

// NewClient creates a new anomaly service client
func NewClient(config *ClientConfig) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		buffer:      make([]*TelemetryEvent, 0, config.BufferSize),
		bufferSize:  0,
		maxBuffer:   config.BufferSize,
		address:     config.ServiceAddress,
		connected:   false,
		ctx:         ctx,
		cancel:      cancel,
		reconnectCh: make(chan struct{}, 1),
	}

	// Attempt initial connection
	if err := client.connect(config.MaxMessageSizeMB); err != nil {
		log.Warn().Err(err).Str("address", config.ServiceAddress).Msg("Failed to connect to anomaly service, will retry")
		// Trigger reconnection attempt
		client.triggerReconnect()
	}

	// Start background goroutines
	client.wg.Add(2) // Track background goroutines
	go func() {
		defer client.wg.Done()
		client.reconnectLoop(config.ReconnectDelay)
	}()
	go func() {
		defer client.wg.Done()
		client.flushLoop(config.FlushInterval)
	}()

	return client, nil
}

// Close closes the client connection and waits for background goroutines to finish
func (c *Client) Close() error {
	c.cancel() // Signal all goroutines to stop

	// Wait for all background goroutines to finish with a timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		// All goroutines finished
	case <-time.After(5 * time.Second):
		log.Warn().Msg("Timed out waiting for background goroutines to finish")
	}

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// connect establishes a connection to the anomaly service
func (c *Client) connect(maxMessageSizeMB int) error {
	// For Arrow Flight services, we need to properly configure the connection
	// Note: WithBlock and WithTimeout options are no longer supported with Dial
	// and should be handled at the RPC level instead

	// Convert MB to bytes for message size limits
	maxMsgSize := maxMessageSizeMB * 1024 * 1024

	// Configure connection options according to gRPC v2 best practices
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgSize),
			grpc.MaxCallSendMsgSize(maxMsgSize),
		),
	}

	// Connect using the newer NewClient method instead of Dial
	// Note: Non-blocking by default - connections happen in the background
	conn, err := grpc.NewClient(c.address, dialOptions...)
	if err != nil {
		return fmt.Errorf("failed to connect to anomaly service: %w", err)
	}

	c.conn = conn
	c.client = blackicev1.NewAnomalyServiceClient(conn)
	c.connected = true

	log.Info().Str("address", c.address).Msg("Connected to anomaly service")
	return nil
}

// reconnectLoop continuously attempts to reconnect to the service
func (c *Client) reconnectLoop(delay time.Duration) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.reconnectCh:
			if !c.connected {
				log.Info().Str("address", c.address).Msg("Attempting to reconnect to anomaly service")
				if err := c.connect(DefaultMaxMessageSizeMB); err != nil {
					log.Error().Err(err).Str("address", c.address).Msg("Failed to reconnect to anomaly service")
					time.Sleep(delay)
					c.triggerReconnect()
				}
			}
		}
	}
}

// triggerReconnect triggers a reconnection attempt
func (c *Client) triggerReconnect() {
	select {
	case c.reconnectCh <- struct{}{}:
	default:
		// Channel already has a pending reconnect request
	}
}

// flushLoop periodically flushes buffered events to the service
func (c *Client) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			// Do one final flush attempt before exiting
			if c.connected {
				if err := c.flushBuffer(); err != nil {
					log.Error().Err(err).Msg("Failed to flush buffer during shutdown")
				}
			}
			return
		case <-ticker.C:
			if c.connected {
				if err := c.flushBuffer(); err != nil {
					log.Error().Err(err).Msg("Failed to flush buffer during periodic flush")
				}
			}
		}
	}
}

// flushBuffer sends buffered events to the service
// Returns an error if the flush operation failed
func (c *Client) flushBuffer() error {
	// Use atomic operations for better performance
	c.bufferMu.Lock()

	// Quick check if buffer is empty
	if c.bufferSize == 0 {
		c.bufferMu.Unlock()
		return nil
	}

	// Create a copy of the buffer for processing
	events := make([]*TelemetryEvent, c.bufferSize)
	copy(events, c.buffer[:c.bufferSize])

	// Clear the buffer but keep the underlying array for reuse
	c.buffer = c.buffer[:0]
	c.bufferSize = 0
	c.bufferMu.Unlock()

	// Nothing to send after all
	if len(events) == 0 {
		return nil
	}

	// Process events in batches if there are many
	const batchSize = 100 // Maximum batch size for each send operation
	var lastError error

	// Send in batches for better reliability
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}

		batch := events[i:end]
		if err := c.sendEventBatch(batch); err != nil {
			log.Error().
				Err(err).
				Int("count", len(batch)).
				Int("batch", i/batchSize+1).
				Int("total_batches", (len(events)+batchSize-1)/batchSize).
				Msg("Failed to send event batch to anomaly service")

			// If sending fails, add events back to buffer
			c.bufferMu.Lock()
			for _, event := range batch {
				c.addToBuffer(event)
			}
			c.bufferMu.Unlock()

			// Mark as disconnected and trigger reconnect
			c.connected = false
			c.triggerReconnect()

			// Store the error to return
			lastError = err

			// Stop processing further batches after failure
			break
		}
	}

	return lastError
}

// sendEventBatch sends a batch of events to the anomaly service
func (c *Client) sendEventBatch(events []*TelemetryEvent) error {
	if !c.connected || c.client == nil {
		return fmt.Errorf("not connected to anomaly service")
	}

	// Create a context with timeout for this batch
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	stream, err := c.client.SubmitTelemetry(ctx)
	if err != nil {
		c.connected = false
		return fmt.Errorf("failed to create telemetry stream: %w", err)
	}

	for _, event := range events {
		protoEvent := ConvertToProto(event)
		if err := stream.Send(protoEvent); err != nil {
			// Try to close the stream before returning
			closeErr := stream.CloseSend()
			if closeErr != nil {
				log.Warn().Err(closeErr).Msg("Failed to close send stream after error")
			}
			c.connected = false
			return fmt.Errorf("failed to send event to stream: %w", err)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		c.connected = false
		return fmt.Errorf("failed to close telemetry stream: %w", err)
	}

	return nil
}

// addToBuffer adds an event to the buffer with respect to the retention policy
func (c *Client) addToBuffer(event *TelemetryEvent) {
	if c.bufferSize >= c.maxBuffer {
		// Buffer is full, apply retention policy
		// For now, just drop the oldest event by default
		c.buffer = c.buffer[1:c.bufferSize]
		c.bufferSize--
	}

	if c.bufferSize < len(c.buffer) {
		c.buffer[c.bufferSize] = event
	} else {
		c.buffer = append(c.buffer, event)
	}
	c.bufferSize++
}

// SendEvent sends a telemetry event to the anomaly service
func (c *Client) SendEvent(event *TelemetryEvent) error {
	if event == nil {
		return fmt.Errorf("cannot send nil event")
	}

	c.bufferMu.Lock()
	c.addToBuffer(event)
	bufferSize := c.bufferSize
	c.bufferMu.Unlock()

	// If buffer is getting full, trigger immediate flush
	if bufferSize >= c.maxBuffer/2 {
		go func() {
			if err := c.flushBuffer(); err != nil {
				log.Error().Err(err).Msg("Failed to flush buffer")
			}
		}()
	}

	return nil
}

// QueryAnomalies queries for anomalies that match the specified criteria
func (c *Client) QueryAnomalies(ctx context.Context, startTime, endTime time.Time, sourceID, detectorID string, minSeverity SeverityLevel) ([]*Anomaly, error) {
	if !c.connected || c.client == nil {
		return nil, fmt.Errorf("not connected to anomaly service")
	}

	req := &blackicev1.QueryAnomaliesRequest{
		StartTimeUnixNs:         startTime.UnixNano(),
		EndTimeUnixNs:           endTime.UnixNano(),
		SourceComponentIdFilter: sourceID,
		DetectorIdFilter:        detectorID,
		MinSeverityFilter:       blackicev1.Anomaly_Severity(minSeverity),
	}

	// Use the client context as parent to ensure cancelation works
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.client.QueryAnomalies(callCtx, req)
	if err != nil {
		c.connected = false
		c.triggerReconnect()
		return nil, fmt.Errorf("failed to query anomalies: %w", err)
	}

	// Convert proto anomalies to internal model
	anomalies := make([]*Anomaly, 0, len(resp.Anomalies))
	for _, protoAnomaly := range resp.Anomalies {
		anomaly := ConvertAnomalyFromProto(protoAnomaly)
		anomalies = append(anomalies, anomaly)
	}

	return anomalies, nil
}

// GetAnomalyDetails gets detailed information about a specific anomaly
func (c *Client) GetAnomalyDetails(ctx context.Context, anomalyID string) (*Anomaly, error) {
	if !c.connected || c.client == nil {
		return nil, fmt.Errorf("not connected to anomaly service")
	}

	req := &blackicev1.GetAnomalyDetailsRequest{
		AnomalyId: anomalyID,
	}

	// Use the client context as parent to ensure cancelation works
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.client.GetAnomalyDetails(callCtx, req)
	if err != nil {
		c.connected = false
		c.triggerReconnect()
		return nil, fmt.Errorf("failed to get anomaly details: %w", err)
	}

	// Convert proto anomaly to internal model
	anomaly := ConvertAnomalyFromProto(resp.AnomalyDetails)
	return anomaly, nil
}

// GetDetectorStatus gets the status of anomaly detectors
func (c *Client) GetDetectorStatus(ctx context.Context, detectorIDs []string) ([]*Detector, error) {
	if !c.connected || c.client == nil {
		return nil, fmt.Errorf("not connected to anomaly service")
	}

	req := &blackicev1.DetectorStatusRequest{
		DetectorIds: detectorIDs,
	}

	// Use the client context as parent to ensure cancelation works
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.client.GetDetectorStatus(callCtx, req)
	if err != nil {
		c.connected = false
		c.triggerReconnect()
		return nil, fmt.Errorf("failed to get detector status: %w", err)
	}

	// Convert proto detectors to internal model
	detectors := make([]*Detector, 0, len(resp.Detectors))
	for _, protoDetector := range resp.Detectors {
		detector := &Detector{
			ID:            protoDetector.DetectorId,
			Type:          protoDetector.DetectorType,
			Version:       protoDetector.Version,
			State:         protoDetector.Status,
			LastProcessed: time.Unix(0, protoDetector.LastEventProcessedUnixNs),
			Parameters:    protoDetector.DetectorParams,
		}
		detectors = append(detectors, detector)
	}

	return detectors, nil
}
