package proxy

import (
	"context"
	"fmt"
	"io"

	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/crypto"
	"github.com/TFMV/blackice/pkg/flightgw/server"
	"github.com/TFMV/blackice/pkg/flightgw/trust"
)

// OperationMode defines the operational mode of the proxy
type OperationMode string

const (
	// PassThroughMode only adds logging and minimal validation
	PassThroughMode OperationMode = "pass-through"

	// TrustBoundaryMode provides full security checks and trust scoring
	TrustBoundaryMode OperationMode = "trust-boundary"

	// TransformMode allows data transformation and filtering
	TransformMode OperationMode = "transform"
)

// SecurityContext holds the security components for the proxy
type SecurityContext struct {
	HMACVerifier        *crypto.HMACVerifier
	AttestationVerifier *crypto.AttestationVerifier
	MerkleVerifier      *crypto.MerkleVerifier
	TrustScorer         *trust.TrustScorer
	Registry            *trust.Registry
}

// FlightProxy manages proxying between Flight clients and servers
type FlightProxy struct {
	cfg              *config.Config
	securityContext  *SecurityContext
	upstreamClient   flight.Client
	mode             OperationMode
	transformers     []DataTransformer
	securityHandlers []SecurityHandler
	circuitBreaker   *server.CircuitBreaker
}

// DataTransformer defines an interface for transforming Flight data
type DataTransformer interface {
	// TransformFlightData transforms Flight data
	TransformFlightData(ctx context.Context, data *flight.FlightData) (*flight.FlightData, error)

	// TransformDescriptor transforms Flight descriptors
	TransformDescriptor(ctx context.Context, desc *flight.FlightDescriptor) (*flight.FlightDescriptor, error)
}

// SecurityHandler defines an interface for handling security operations
type SecurityHandler interface {
	// Name returns the name of the handler
	Name() string

	// Priority returns the priority of the handler (lower runs first)
	Priority() int

	// HandleIncoming processes incoming data
	HandleIncoming(ctx context.Context, data interface{}) (interface{}, error)

	// HandleOutgoing processes outgoing data
	HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error)
}

// NewFlightProxy creates a new Flight proxy
func NewFlightProxy(
	cfg *config.Config,
	secCtx *SecurityContext,
	upstreamClient flight.Client,
	circuitBreaker *server.CircuitBreaker,
) (*FlightProxy, error) {
	// Determine the operation mode
	mode := PassThroughMode
	switch cfg.Proxy.Mode {
	case "pass-through":
		mode = PassThroughMode
	case "trust-boundary":
		mode = TrustBoundaryMode
	case "transform":
		mode = TransformMode
	default:
		log.Warn().
			Str("configured_mode", cfg.Proxy.Mode).
			Str("fallback_mode", string(PassThroughMode)).
			Msg("Unknown operation mode configured, falling back to pass-through")
	}

	proxy := &FlightProxy{
		cfg:              cfg,
		securityContext:  secCtx,
		upstreamClient:   upstreamClient,
		mode:             mode,
		transformers:     []DataTransformer{},
		securityHandlers: []SecurityHandler{},
		circuitBreaker:   circuitBreaker,
	}

	// Register security handlers based on configured mode
	if err := proxy.registerSecurityHandlers(); err != nil {
		return nil, fmt.Errorf("failed to register security handlers: %w", err)
	}

	// Register transformers if in transform mode
	if mode == TransformMode {
		if err := proxy.registerTransformers(); err != nil {
			return nil, fmt.Errorf("failed to register transformers: %w", err)
		}
	}

	log.Info().
		Str("mode", string(mode)).
		Msg("Flight proxy initialized")

	return proxy, nil
}

// registerSecurityHandlers registers security handlers based on the operational mode
func (p *FlightProxy) registerSecurityHandlers() error {
	// Register common handlers for all modes
	p.securityHandlers = append(p.securityHandlers, &LoggingHandler{priority: 0})

	// For trust-boundary and transform modes, add security validation
	if p.mode == TrustBoundaryMode || p.mode == TransformMode {
		// Add HMAC verification if enabled
		if p.securityContext.HMACVerifier != nil {
			p.securityHandlers = append(p.securityHandlers,
				&HMACHandler{
					verifier: p.securityContext.HMACVerifier,
					priority: 10,
				},
			)
		}

		// Add attestation verification if enabled
		if p.securityContext.AttestationVerifier != nil {
			p.securityHandlers = append(p.securityHandlers,
				&AttestationHandler{
					verifier: p.securityContext.AttestationVerifier,
					priority: 20,
				},
			)
		}

		// Add Merkle verification if enabled
		if p.securityContext.MerkleVerifier != nil {
			p.securityHandlers = append(p.securityHandlers,
				&MerkleStreamHandler{
					verifier: p.securityContext.MerkleVerifier,
					priority: 30,
				},
			)
		}

		// Add trust scoring handler
		if p.securityContext.TrustScorer != nil && p.securityContext.Registry != nil {
			p.securityHandlers = append(p.securityHandlers,
				&TrustScoringHandler{
					scorer:   p.securityContext.TrustScorer,
					registry: p.securityContext.Registry,
					priority: 40,
				},
			)
		}
	}

	// Sort handlers by priority
	sortHandlersByPriority(p.securityHandlers)

	return nil
}

// registerTransformers registers data transformers for transform mode
func (p *FlightProxy) registerTransformers() error {
	// In a real implementation, we would load transformers from configuration
	// or from a plugin system

	// For now, we'll just add a simple pass-through transformer
	p.transformers = append(p.transformers, &PassThroughTransformer{})

	return nil
}

// ProxyGet handles proxying DoGet operations
func (p *FlightProxy) ProxyGet(ctx context.Context, ticket *flight.Ticket, outStream flight.FlightService_DoGetServer) error {
	// Process the ticket through security handlers
	processedTicket, err := p.processIncoming(ctx, ticket)
	if err != nil {
		return err
	}

	finalTicket, ok := processedTicket.(*flight.Ticket)
	if !ok {
		return fmt.Errorf("unexpected ticket type after processing: %T", processedTicket)
	}

	// Get data from upstream
	upstreamStream, err := p.upstreamClient.DoGet(ctx, finalTicket)
	if err != nil {
		return err
	}

	// Stream data back to the client with security processing
	for {
		data, err := upstreamStream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Process outgoing data through security handlers
		processedData, err := p.processOutgoing(ctx, data)
		if err != nil {
			return err
		}

		finalData, ok := processedData.(*flight.FlightData)
		if !ok {
			return fmt.Errorf("unexpected data type after processing: %T", processedData)
		}

		// If we're in transform mode, apply transformations
		if p.mode == TransformMode {
			for _, transformer := range p.transformers {
				finalData, err = transformer.TransformFlightData(ctx, finalData)
				if err != nil {
					log.Error().Err(err).Msg("Failed to transform flight data")
					return err
				}
			}
		}

		if err := outStream.Send(finalData); err != nil {
			return err
		}
	}
}

// ProxyPut handles proxying DoPut operations
func (p *FlightProxy) ProxyPut(ctx context.Context, inStream flight.FlightService_DoPutServer) error {
	putDone := make(chan struct{})
	errorCh := make(chan error, 2)

	// Get the upstream client
	upstreamStream, err := p.upstreamClient.DoPut(ctx)
	if err != nil {
		return fmt.Errorf("failed to create upstream put stream: %w", err)
	}

	// Stream data to the upstream service
	go func() {
		for {
			chunk, err := inStream.Recv()
			if err != nil {
				errorCh <- err
				close(putDone)
				return
			}

			// Process incoming data through security handlers
			processedChunk, err := p.processIncoming(ctx, chunk)
			if err != nil {
				errorCh <- err
				close(putDone)
				return
			}

			finalChunk, ok := processedChunk.(*flight.FlightData)
			if !ok {
				errorCh <- fmt.Errorf("unexpected chunk type after processing: %T", processedChunk)
				close(putDone)
				return
			}

			// Apply transformations if in transform mode
			if p.mode == TransformMode {
				for _, transformer := range p.transformers {
					finalChunk, err = transformer.TransformFlightData(ctx, finalChunk)
					if err != nil {
						errorCh <- fmt.Errorf("failed to transform flight data: %w", err)
						close(putDone)
						return
					}
				}
			}

			if err := upstreamStream.Send(finalChunk); err != nil {
				errorCh <- err
				close(putDone)
				return
			}
		}
	}()

	// Receive results from the upstream service
	go func() {
		for {
			result, err := upstreamStream.Recv()
			if err != nil {
				errorCh <- err
				return
			}

			// Process outgoing data through security handlers
			processedResult, err := p.processOutgoing(ctx, result)
			if err != nil {
				errorCh <- err
				return
			}

			// The result from DoPut is already a PutResult type
			putResult, ok := processedResult.(*flight.PutResult)
			if !ok {
				errorCh <- fmt.Errorf("unexpected result type after processing: %T", processedResult)
				return
			}

			if err := inStream.Send(putResult); err != nil {
				errorCh <- err
				return
			}
		}
	}()

	// Wait for completion or error
	select {
	case <-putDone:
		return nil
	case err := <-errorCh:
		if err == io.EOF {
			return nil
		}
		return err
	}
}

// ProxyGetFlightInfo proxies GetFlightInfo operations
func (p *FlightProxy) ProxyGetFlightInfo(ctx context.Context, descriptor *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	// Process the descriptor through security handlers
	processedDesc, err := p.processIncoming(ctx, descriptor)
	if err != nil {
		return nil, err
	}

	finalDesc, ok := processedDesc.(*flight.FlightDescriptor)
	if !ok {
		return nil, fmt.Errorf("unexpected descriptor type after processing: %T", processedDesc)
	}

	// Apply transformations if in transform mode
	if p.mode == TransformMode {
		for _, transformer := range p.transformers {
			finalDesc, err = transformer.TransformDescriptor(ctx, finalDesc)
			if err != nil {
				return nil, fmt.Errorf("failed to transform flight descriptor: %w", err)
			}
		}
	}

	// Get flight info from upstream
	info, err := p.upstreamClient.GetFlightInfo(ctx, finalDesc)
	if err != nil {
		return nil, err
	}

	// Process outgoing info through security handlers
	processedInfo, err := p.processOutgoing(ctx, info)
	if err != nil {
		return nil, err
	}

	finalInfo, ok := processedInfo.(*flight.FlightInfo)
	if !ok {
		return nil, fmt.Errorf("unexpected info type after processing: %T", processedInfo)
	}

	return finalInfo, nil
}

// processIncoming processes incoming data through all security handlers
func (p *FlightProxy) processIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	var err error
	result := data

	for _, handler := range p.securityHandlers {
		result, err = handler.HandleIncoming(ctx, result)
		if err != nil {
			log.Error().
				Err(err).
				Str("handler", handler.Name()).
				Msg("Security handler failed for incoming data")
			return nil, err
		}
	}

	return result, nil
}

// processOutgoing processes outgoing data through all security handlers
func (p *FlightProxy) processOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	var err error
	result := data

	for _, handler := range p.securityHandlers {
		result, err = handler.HandleOutgoing(ctx, result)
		if err != nil {
			log.Error().
				Err(err).
				Str("handler", handler.Name()).
				Msg("Security handler failed for outgoing data")
			return nil, err
		}
	}

	return result, nil
}

// sortHandlersByPriority sorts handlers by priority
func sortHandlersByPriority(handlers []SecurityHandler) {
	// Simple bubble sort for now (handlers list is typically small)
	for i := 0; i < len(handlers)-1; i++ {
		for j := 0; j < len(handlers)-i-1; j++ {
			if handlers[j].Priority() > handlers[j+1].Priority() {
				handlers[j], handlers[j+1] = handlers[j+1], handlers[j]
			}
		}
	}
}

//
// Handler Implementations
//

// LoggingHandler logs all traffic
type LoggingHandler struct {
	priority int
}

func (h *LoggingHandler) Name() string {
	return "logging"
}

func (h *LoggingHandler) Priority() int {
	return h.priority
}

func (h *LoggingHandler) HandleIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	log.Debug().
		Str("direction", "incoming").
		Str("type", fmt.Sprintf("%T", data)).
		Msg("Processing data")
	return data, nil
}

func (h *LoggingHandler) HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	log.Debug().
		Str("direction", "outgoing").
		Str("type", fmt.Sprintf("%T", data)).
		Msg("Processing data")
	return data, nil
}

// HMACHandler verifies HMAC signatures
type HMACHandler struct {
	verifier *crypto.HMACVerifier
	priority int
}

func (h *HMACHandler) Name() string {
	return "hmac"
}

func (h *HMACHandler) Priority() int {
	return h.priority
}

func (h *HMACHandler) HandleIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we would extract HMAC from metadata
	// and verify it for different types of data
	return data, nil
}

func (h *HMACHandler) HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we might add HMAC signatures to outgoing data
	return data, nil
}

// AttestationHandler verifies attestations
type AttestationHandler struct {
	verifier *crypto.AttestationVerifier
	priority int
}

func (h *AttestationHandler) Name() string {
	return "attestation"
}

func (h *AttestationHandler) Priority() int {
	return h.priority
}

func (h *AttestationHandler) HandleIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we would extract attestations and verify them
	return data, nil
}

func (h *AttestationHandler) HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we might add attestations to outgoing data
	return data, nil
}

// MerkleStreamHandler verifies Merkle stream proofs
type MerkleStreamHandler struct {
	verifier *crypto.MerkleVerifier
	priority int
}

func (h *MerkleStreamHandler) Name() string {
	return "merkle"
}

func (h *MerkleStreamHandler) Priority() int {
	return h.priority
}

func (h *MerkleStreamHandler) HandleIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we would extract Merkle proofs and verify them
	return data, nil
}

func (h *MerkleStreamHandler) HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we might add Merkle proofs to outgoing data
	return data, nil
}

// TrustScoringHandler handles trust scoring
type TrustScoringHandler struct {
	scorer   *trust.TrustScorer
	registry *trust.Registry
	priority int
}

func (h *TrustScoringHandler) Name() string {
	return "trust-scoring"
}

func (h *TrustScoringHandler) Priority() int {
	return h.priority
}

func (h *TrustScoringHandler) HandleIncoming(ctx context.Context, data interface{}) (interface{}, error) {
	// In a real implementation, we would:
	// 1. Extract source ID from data
	// 2. Check if source is registered
	// 3. Update trust score based on data characteristics
	// 4. Reject if trust score is too low
	return data, nil
}

func (h *TrustScoringHandler) HandleOutgoing(ctx context.Context, data interface{}) (interface{}, error) {
	// Trust scoring typically doesn't modify outgoing data
	return data, nil
}

//
// Transformer Implementations
//

// PassThroughTransformer is a simple transformer that passes data through unchanged
type PassThroughTransformer struct{}

func (t *PassThroughTransformer) TransformFlightData(ctx context.Context, data *flight.FlightData) (*flight.FlightData, error) {
	return data, nil
}

func (t *PassThroughTransformer) TransformDescriptor(ctx context.Context, desc *flight.FlightDescriptor) (*flight.FlightDescriptor, error) {
	return desc, nil
}

// ProxyDoGet proxies DoGet requests to the upstream server
func (p *FlightProxy) ProxyDoGet(
	ctx context.Context,
	ticket *flight.Ticket,
	writer flight.FlightService_DoGetServer,
) error {
	// Verify that upstream client is available
	if p.upstreamClient == nil {
		return status.Error(codes.Unavailable, "upstream client not configured")
	}

	// Convert the ticket and add appropriate headers
	proxyTicket, err := p.convertTicket(ctx, ticket)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to convert ticket: %v", err)
	}

	// Execute the upstream request with circuit breaker protection
	var reader flight.FlightService_DoGetClient
	err = p.circuitBreaker.Execute(func() error {
		var reqErr error
		reader, reqErr = p.upstreamClient.DoGet(ctx, proxyTicket)
		return reqErr
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to execute DoGet on upstream server")
		return status.Errorf(codes.Internal, "upstream DoGet request failed: %v", err)
	}

	// Proxy the response stream
	return p.proxyStream(reader, writer)
}

// convertTicket prepares a Flight ticket for proxying to upstream
func (p *FlightProxy) convertTicket(ctx context.Context, ticket *flight.Ticket) (*flight.Ticket, error) {
	// In a real implementation, this might:
	// 1. Add security metadata
	// 2. Verify client permissions
	// 3. Transform the ticket based on policy

	// For now, we just return the original ticket
	return ticket, nil
}

// proxyStream handles copying data between Flight streams
func (p *FlightProxy) proxyStream(reader flight.FlightService_DoGetClient, writer flight.FlightService_DoGetServer) error {
	for {
		data, err := reader.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			log.Error().Err(err).Msg("Error receiving data from upstream")
			return err
		}

		// Process data through handlers
		processedData, err := p.processOutgoing(writer.Context(), data)
		if err != nil {
			return err
		}

		finalData, ok := processedData.(*flight.FlightData)
		if !ok {
			return fmt.Errorf("unexpected data type after processing: %T", processedData)
		}

		if err := writer.Send(finalData); err != nil {
			log.Error().Err(err).Msg("Error sending data to client")
			return err
		}
	}
}
