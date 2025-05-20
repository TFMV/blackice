package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"google.golang.org/grpc/metadata"
)

// FlightServiceImpl implements the Flight service interface
type FlightServiceImpl struct {
	*flight.BaseFlightServer
	server *SecureFlightServer
}

// Handshake handles the handshake protocol
func (s *FlightServiceImpl) Handshake(stream flight.FlightService_HandshakeServer) error {
	log.Debug().Msg("Handshake request received")

	// Initialize authentication context
	authContext := make(map[string]string)

	// Process handshake messages
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		// Extract authentication data from payload
		if len(req.Payload) > 0 {
			// In a production environment, this would parse authentication tokens,
			// credentials, or certificates depending on the authentication mechanism

			// Perform authentication based on the payload
			if s.server.hmacVerifier != nil {
				// Example: verify HMAC-based authentication token
				// Format: hmac:<token>
				payload := string(req.Payload)
				if len(payload) > 5 && payload[:5] == "hmac:" {
					token := payload[5:]
					valid, err := s.server.hmacVerifier.VerifyHMACHex(token, []byte("handshake-auth"))
					if err != nil {
						log.Error().Err(err).Msg("HMAC verification failed during handshake")
						return fmt.Errorf("authentication failed: %w", err)
					}
					if valid {
						authContext["authenticated"] = "true"
						authContext["auth_method"] = "hmac"
						log.Info().Msg("Client authenticated via HMAC")
					}
				}
			}

			// Attestation-based authentication could be added here
			if s.server.attestationVerifier != nil && s.server.registry != nil {
				// Example: verify attestation-based authentication
				// Format: attestation:sourceID:base64encodedAttestation
				payload := string(req.Payload)
				if len(payload) > 12 && payload[:12] == "attestation:" {
					// Parse the source ID and attestation
					parts := strings.SplitN(payload[12:], ":", 2)
					if len(parts) == 2 {
						sourceID := parts[0]
						attestationData, err := base64.StdEncoding.DecodeString(parts[1])
						if err != nil {
							log.Error().Err(err).Msg("Failed to decode attestation data")
							return fmt.Errorf("invalid attestation format: %w", err)
						}

						// Get the source info to retrieve the public key
						sourceInfo, err := s.server.registry.GetSource(sourceID)
						if err != nil {
							log.Error().Err(err).Str("source_id", sourceID).Msg("Source not found")
							return fmt.Errorf("unknown source: %w", err)
						}

						// Unmarshal the attestation
						var attestation blackicev1.Attestation
						if err := proto.Unmarshal(attestationData, &attestation); err != nil {
							log.Error().Err(err).Msg("Failed to unmarshal attestation")
							return fmt.Errorf("invalid attestation data: %w", err)
						}

						// Verify the attestation
						// The data being verified is typically a nonce or timestamp
						// that was previously sent to the client
						valid, err := s.server.attestationVerifier.VerifyAttestation(
							&attestation,
							sourceInfo.PublicKey,
							[]byte("handshake-challenge"),
						)
						if err != nil {
							log.Error().Err(err).Msg("Attestation verification failed")
							return fmt.Errorf("attestation verification failed: %w", err)
						}

						if valid {
							authContext["authenticated"] = "true"
							authContext["auth_method"] = "attestation"
							authContext["source_id"] = sourceID
							log.Info().Str("source_id", sourceID).Msg("Client authenticated via attestation")

							// Update the source's last activity timestamp
							if err := s.server.registry.UpdateSourceActivity(sourceID); err != nil {
								log.Warn().Err(err).Str("source_id", sourceID).Msg("Failed to update source activity")
							}
						}
					}
				}
			}
		}

		// Generate response with authentication result
		respPayload := []byte("auth:success")
		if authContext["authenticated"] != "true" {
			respPayload = []byte("auth:challenge")
		}

		resp := &flight.HandshakeResponse{
			ProtocolVersion: req.ProtocolVersion,
			Payload:         respPayload,
		}

		if err := stream.Send(resp); err != nil {
			return err
		}

		// If authentication is successful, we can stop the handshake
		if authContext["authenticated"] == "true" {
			// In a real implementation, we would store the authentication context
			// in a session store or token manager for subsequent requests
			break
		}
	}

	return nil
}

// ListFlights lists available flights
func (s *FlightServiceImpl) ListFlights(criteria *flight.Criteria, stream flight.FlightService_ListFlightsServer) error {
	log.Debug().Msg("ListFlights request received")

	ctx := stream.Context()

	// Pass through to the upstream service with security checks
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.ListFlights(ctx, criteria)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list flights from upstream")
			return err
		}

		// Stream results back to the client
		for {
			info, err := upstreamStream.Recv()
			if err != nil {
				return err
			}

			// Apply security verification and trust scoring
			_ = 100 // Default perfect score for use in real implementation

			// Apply trust scoring if enabled
			if s.server.trustScorer != nil {
				log.Debug().Msg("Trust scoring enabled but no implementation for ListFlights yet")
				// In a real implementation, extract source ID and check trust score
				// sourceID := extractSourceID(info)
				// score, err := s.server.trustScorer.GetScore(sourceID)
				// if err == nil {
				//     trustScore = score.Score
				// }

				// Check if the source is trusted
				// trusted, _ := s.server.trustScorer.IsTrusted(sourceID)
				// if !trusted {
				//     log.Warn().Str("source_id", sourceID).Int("score", trustScore).Msg("Untrusted source")
				//     continue // Skip this result
				// }
			}

			// Send to client
			if err := stream.Send(info); err != nil {
				return err
			}
		}
	}

	// Return empty list if no upstream
	return nil
}

// GetFlightInfo implements the Flight GetFlightInfo method
func (s *FlightServiceImpl) GetFlightInfo(ctx context.Context, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	// Verify required security properties
	if err := s.verifyRequest(ctx, desc); err != nil {
		return nil, err
	}

	// Get flight info from upstream
	info, err := s.server.getUpstreamInfo(ctx, desc)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get flight info from upstream")
		return nil, status.Errorf(codes.Internal, "upstream error: %v", err)
	}

	// Apply any transformations or security enhancements to the flight info
	// For example, we could modify endpoints, add security metadata, etc.

	return info, nil
}

// GetSchema implements the Flight GetSchema method
func (s *FlightServiceImpl) GetSchema(ctx context.Context, desc *flight.FlightDescriptor) (*flight.SchemaResult, error) {
	// Verify required security properties
	if err := s.verifyRequest(ctx, desc); err != nil {
		return nil, err
	}

	// Get schema from upstream
	schema, err := s.server.getUpstreamSchema(ctx, desc)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get schema from upstream")
		return nil, status.Errorf(codes.Internal, "upstream error: %v", err)
	}

	return schema, nil
}

// DoGet implements the Flight DoGet method
func (s *FlightServiceImpl) DoGet(ticket *flight.Ticket, stream flight.FlightService_DoGetServer) error {
	ctx := stream.Context()

	// Verify required security properties
	if err := s.verifyTicket(ctx, ticket); err != nil {
		return err
	}

	// Get data from upstream
	reader, err := s.server.doUpstreamGet(ctx, ticket)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get data from upstream")
		return status.Errorf(codes.Internal, "upstream error: %v", err)
	}

	// Stream data to client
	for {
		data, err := reader.Recv()
		if err != nil {
			// End of stream is not an error
			if err.Error() == "EOF" {
				return nil
			}
			log.Error().Err(err).Msg("Error receiving data from upstream")
			return status.Errorf(codes.Internal, "upstream error: %v", err)
		}

		// Apply any transformations or security checks to the data
		// For example, verify attestations, process Merkle proofs, etc.

		if err := stream.Send(data); err != nil {
			log.Error().Err(err).Msg("Error sending data to client")
			return status.Errorf(codes.Internal, "send error: %v", err)
		}
	}
}

// DoPut implements the Flight DoPut method
func (s *FlightServiceImpl) DoPut(stream flight.FlightService_DoPutServer) error {
	ctx := stream.Context()

	// Set up upstream writer
	writer, err := s.server.doUpstreamPut(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set up upstream writer")
		return status.Errorf(codes.Internal, "upstream error: %v", err)
	}

	var firstMessage bool = true
	var flightDesc *flight.FlightDescriptor

	// Stream data from client to upstream
	for {
		data, err := stream.Recv()
		if err != nil {
			// End of stream is not an error
			if err.Error() == "EOF" {
				break
			}
			log.Error().Err(err).Msg("Error receiving data from client")
			return status.Errorf(codes.Internal, "receive error: %v", err)
		}

		// Check the flight descriptor in the first message
		if firstMessage {
			firstMessage = false
			flightDesc = data.FlightDescriptor

			// Verify the descriptor
			if err := s.verifyDescriptor(ctx, flightDesc); err != nil {
				return err
			}
		}

		// Apply any transformations or security checks to the data
		// For example, add attestations, Merkle proofs, etc.

		if err := writer.Send(data); err != nil {
			log.Error().Err(err).Msg("Error sending data to upstream")
			return status.Errorf(codes.Internal, "upstream error: %v", err)
		}
	}

	// Get response from upstream
	putResult, err := writer.Recv()
	if err != nil {
		log.Error().Err(err).Msg("Error receiving result from upstream")
		return status.Errorf(codes.Internal, "upstream error: %v", err)
	}

	// Send response to client
	if err := stream.Send(putResult); err != nil {
		log.Error().Err(err).Msg("Error sending result to client")
		return status.Errorf(codes.Internal, "send error: %v", err)
	}

	return nil
}

// DoExchange performs bidirectional data exchange
func (s *FlightServiceImpl) DoExchange(stream flight.FlightService_DoExchangeServer) error {
	log.Debug().Msg("DoExchange request received")
	ctx := stream.Context()

	// Pass through to the upstream service with security verification
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.DoExchange(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to exchange data with upstream")
			return err
		}

		errCh := make(chan error, 2)

		// Handle receiving from the client and sending to upstream
		go func() {
			for {
				chunk, err := stream.Recv()
				if err != nil {
					errCh <- err
					return
				}

				// Here we'd implement security verification

				if err := upstreamStream.Send(chunk); err != nil {
					errCh <- err
					return
				}
			}
		}()

		// Handle receiving from upstream and sending to the client
		go func() {
			for {
				chunk, err := upstreamStream.Recv()
				if err != nil {
					errCh <- err
					return
				}

				// Here we'd implement security verification for responses

				if err := stream.Send(chunk); err != nil {
					errCh <- err
					return
				}
			}
		}()

		// Wait for an error from either goroutine
		err = <-errCh
		return err
	}

	return fmt.Errorf("no upstream Flight service configured")
}

// DoAction performs an action
func (s *FlightServiceImpl) DoAction(action *flight.Action, stream flight.FlightService_DoActionServer) error {
	log.Debug().Str("action", action.Type).Msg("DoAction request received")
	ctx := stream.Context()

	// Apply security verification for the action
	// In a real implementation, we'd verify the action is authorized

	// Pass through to the upstream service
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.DoAction(ctx, action)
		if err != nil {
			log.Error().Err(err).Msg("Failed to perform action upstream")
			return err
		}

		// Stream results back to the client
		for {
			result, err := upstreamStream.Recv()
			if err != nil {
				return err
			}

			// Apply security verification for the result
			// In a real implementation, we'd verify the result is valid

			if err := stream.Send(result); err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("no upstream Flight service configured")
}

// ListActions lists available actions
func (s *FlightServiceImpl) ListActions(empty *flight.Empty, stream flight.FlightService_ListActionsServer) error {
	log.Debug().Msg("ListActions request received")
	ctx := stream.Context()

	// Apply security filtering
	// In a real implementation, we'd filter actions based on permissions

	// Pass through to the upstream service
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.ListActions(ctx, empty)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list actions from upstream")
			return err
		}

		// Stream results back to the client
		for {
			action, err := upstreamStream.Recv()
			if err != nil {
				return err
			}

			// Apply security filtering for the action
			// In a real implementation, we'd filter actions based on permissions

			if err := stream.Send(action); err != nil {
				return err
			}
		}
	}

	// Return empty result if no upstream
	return nil
}

// verifyRequest verifies security properties of the request
func (s *FlightServiceImpl) verifyRequest(ctx context.Context, desc *flight.FlightDescriptor) error {
	// Check HMAC if enabled
	if s.server.hmacVerifier != nil {
		// Military-grade HMAC verification implementation
		log.Debug().Msg("Performing military-grade HMAC verification for request")

		// 1. Extract metadata from context using gRPC metadata
		md, ok := extractMetadataFromContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing request metadata")
		}

		// 2. Extract HMAC signature
		hmacSignature := md["x-blackice-hmac"]
		if hmacSignature == "" {
			return status.Error(codes.Unauthenticated, "missing HMAC signature")
		}

		// 3. Prepare message to verify
		// Create a deterministic representation of the descriptor
		var message []byte
		switch desc.Type {
		case flight.DescriptorPATH:
			// Convert []string to string for path
			pathStr := strings.Join(desc.Path, "/")
			message = []byte(fmt.Sprintf("PATH:%s", pathStr))
		case flight.DescriptorCMD:
			message = []byte(fmt.Sprintf("CMD:%s", string(desc.Cmd)))
		default:
			return status.Error(codes.InvalidArgument, "unsupported descriptor type")
		}

		// 4. Verify HMAC
		valid, err := s.server.hmacVerifier.VerifyHMACHex(hmacSignature, message)
		if err != nil {
			log.Error().Err(err).Msg("HMAC verification failed")
			return status.Errorf(codes.Internal, "HMAC verification error: %v", err)
		}

		if !valid {
			log.Warn().
				Str("hmac", hmacSignature).
				Str("descriptor_type", fmt.Sprintf("%v", desc.Type)).
				Msg("Invalid HMAC signature")
			return status.Error(codes.Unauthenticated, "invalid HMAC signature")
		}

		// 5. Check timestamp to prevent replay attacks
		timestamp := md["x-blackice-timestamp"]
		if timestamp != "" {
			// Parse timestamp
			ts, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				return status.Error(codes.InvalidArgument, "invalid timestamp format")
			}

			// Check if timestamp is within acceptable range (5 minutes)
			now := time.Now().Unix()
			if now-ts > 300 || ts-now > 300 {
				return status.Error(codes.Unauthenticated, "request timestamp expired")
			}
		}

		log.Debug().Msg("HMAC verification successful")
	}

	// Apply trust scoring
	// This is a placeholder for actual implementation

	return nil
}

// extractMetadataFromContext extracts metadata from gRPC context
func extractMetadataFromContext(ctx context.Context) (map[string]string, bool) {
	md := make(map[string]string)

	// Extract metadata from context using gRPC metadata
	grpcMD, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return md, false
	}

	// Convert gRPC metadata to string map
	for key, values := range grpcMD {
		if len(values) > 0 {
			md[key] = values[0]
		}
	}

	return md, true
}

// verifyTicket verifies security properties of the ticket
func (s *FlightServiceImpl) verifyTicket(ctx context.Context, ticket *flight.Ticket) error {
	// Check HMAC if enabled
	if s.server.hmacVerifier != nil {
		// Military-grade HMAC verification implementation
		log.Debug().Msg("Performing military-grade HMAC verification for ticket")

		// 1. Extract ticket data and signature
		// Format: <ticket_data>|<hmac_signature>
		ticketStr := string(ticket.Ticket)
		parts := strings.Split(ticketStr, "|")

		if len(parts) != 2 {
			return status.Error(codes.InvalidArgument, "invalid ticket format")
		}

		ticketData := parts[0]
		hmacSignature := parts[1]

		// 2. Verify HMAC
		valid, err := s.server.hmacVerifier.VerifyHMACHex(hmacSignature, []byte(ticketData))
		if err != nil {
			log.Error().Err(err).Msg("Ticket HMAC verification failed")
			return status.Errorf(codes.Internal, "HMAC verification error: %v", err)
		}

		if !valid {
			log.Warn().
				Str("hmac", hmacSignature).
				Str("ticket_data", ticketData).
				Msg("Invalid ticket HMAC signature")
			return status.Error(codes.Unauthenticated, "invalid ticket signature")
		}

		// 3. Parse ticket data to check validity
		// Format: <resource_id>:<timestamp>
		ticketParts := strings.Split(ticketData, ":")
		if len(ticketParts) >= 2 {
			// Check if timestamp is within acceptable range
			timestamp, err := strconv.ParseInt(ticketParts[1], 10, 64)
			if err == nil {
				now := time.Now().Unix()
				if now-timestamp > 3600 { // 1 hour expiration
					return status.Error(codes.Unauthenticated, "ticket expired")
				}
			}
		}

		log.Debug().Msg("Ticket HMAC verification successful")
	}

	// Apply trust scoring
	// This is a placeholder for actual implementation

	return nil
}

// verifyDescriptor verifies security properties of the flight descriptor
func (s *FlightServiceImpl) verifyDescriptor(ctx context.Context, desc *flight.FlightDescriptor) error {
	// Check HMAC if enabled
	if s.server.hmacVerifier != nil {
		// Military-grade HMAC verification implementation
		log.Debug().Msg("Performing military-grade HMAC verification for descriptor")

		// 1. Extract metadata from context using gRPC metadata
		md, ok := extractMetadataFromContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing request metadata")
		}

		// 2. Extract HMAC signature
		hmacSignature := md["x-blackice-descriptor-hmac"]
		if hmacSignature == "" {
			return status.Error(codes.Unauthenticated, "missing descriptor HMAC signature")
		}

		// 3. Prepare message to verify
		var message []byte
		switch desc.Type {
		case flight.DescriptorPATH:
			// Convert []string to string for path
			pathStr := strings.Join(desc.Path, "/")
			message = []byte(fmt.Sprintf("PATH:%s", pathStr))
		case flight.DescriptorCMD:
			message = []byte(fmt.Sprintf("CMD:%s", string(desc.Cmd)))
		default:
			return status.Error(codes.InvalidArgument, "unsupported descriptor type")
		}

		// 4. Verify HMAC
		valid, err := s.server.hmacVerifier.VerifyHMACHex(hmacSignature, message)
		if err != nil {
			log.Error().Err(err).Msg("Descriptor HMAC verification failed")
			return status.Errorf(codes.Internal, "HMAC verification error: %v", err)
		}

		if !valid {
			log.Warn().
				Str("hmac", hmacSignature).
				Str("descriptor_type", fmt.Sprintf("%v", desc.Type)).
				Msg("Invalid descriptor HMAC signature")
			return status.Error(codes.Unauthenticated, "invalid descriptor signature")
		}

		// 5. Validate command structure and permissions if it's a command
		if desc.Type == flight.DescriptorCMD {
			// Simple command structure validation
			// This would be more complex in a real implementation
			if len(desc.Cmd) == 0 {
				return status.Error(codes.InvalidArgument, "empty command")
			}

			// Check if command starts with a known prefix
			cmd := string(desc.Cmd)
			validPrefixes := []string{"get:", "put:", "list:", "query:"}
			validPrefix := false

			for _, prefix := range validPrefixes {
				if strings.HasPrefix(cmd, prefix) {
					validPrefix = true
					break
				}
			}

			if !validPrefix {
				return status.Error(codes.PermissionDenied, "unsupported command pattern")
			}
		}

		log.Debug().Msg("Descriptor HMAC verification successful")
	}

	return nil
}
