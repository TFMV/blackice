package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/apache/arrow/go/v18/arrow"
	"github.com/apache/arrow/go/v18/arrow/flight"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/crypto"
	"github.com/TFMV/blackice/pkg/flightgw/trust"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// SecureFlightServer is a secure implementation of the Arrow Flight server
type SecureFlightServer struct {
	cfg                 *config.Config
	hmacVerifier        *crypto.HMACVerifier
	trustScorer         *trust.TrustScorer
	registry            *trust.Registry
	attestationVerifier *crypto.AttestationVerifier
	merkleVerifier      *crypto.MerkleVerifier
	upstreamClient      flight.Client
	grpcServer          *grpc.Server
	securityContext     *SecurityContext
	initialized         bool
	listener            net.Listener
}

// SecurityContext holds security components for handlers
type SecurityContext struct {
	HMACVerifier        *crypto.HMACVerifier
	AttestationVerifier *crypto.AttestationVerifier
	MerkleVerifier      *crypto.MerkleVerifier
	TrustScorer         *trust.TrustScorer
	Registry            *trust.Registry
}

// NewSecureFlightServer creates a new secure Flight server
func NewSecureFlightServer(cfg *config.Config) (*SecureFlightServer, error) {
	server := &SecureFlightServer{
		cfg: cfg,
	}

	// Initialize trust scorer
	server.trustScorer = trust.NewTrustScorer(
		cfg.Security.MinTrustScore,
		cfg.Security.TrustScoreThreshold,
	)

	// Initialize registry
	server.registry = trust.NewRegistry(server.trustScorer)

	// Initialize HMAC verifier if enabled
	if cfg.Security.EnableHMAC {
		var err error
		server.hmacVerifier, err = crypto.NewHMACVerifier(
			cfg.Security.HMACAlgorithm,
			cfg.Security.HMACSecretPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HMAC verifier: %w", err)
		}
		log.Info().Msg("HMAC verification enabled")
	} else {
		log.Info().Msg("HMAC verification disabled")
	}

	// Initialize attestation verifier if enabled
	if cfg.Security.EnableAttestations {
		var err error
		server.attestationVerifier, err = crypto.NewAttestationVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize attestation verifier: %w", err)
		}
		log.Info().Msg("Attestation verification enabled")
	} else {
		log.Info().Msg("Attestation verification disabled")
	}

	// Initialize Merkle verifier if enabled
	if cfg.Security.EnableMerkleVerify {
		var err error
		server.merkleVerifier, err = crypto.NewMerkleVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Merkle verifier: %w", err)
		}
		log.Info().Msg("Merkle verification enabled")
	} else {
		log.Info().Msg("Merkle verification disabled")
	}

	// Initialize security context for handlers
	server.securityContext = &SecurityContext{
		HMACVerifier:        server.hmacVerifier,
		AttestationVerifier: server.attestationVerifier,
		MerkleVerifier:      server.merkleVerifier,
		TrustScorer:         server.trustScorer,
		Registry:            server.registry,
	}

	// Create the upstream client
	if err := server.setupUpstreamClient(); err != nil {
		return nil, fmt.Errorf("failed to set up upstream client: %w", err)
	}

	server.initialized = true
	return server, nil
}

// setupUpstreamClient sets up the Flight client to the upstream service
func (s *SecureFlightServer) setupUpstreamClient() error {
	clientCfg := s.cfg.Client

	// Set up client TLS options
	var opts []grpc.DialOption
	if clientCfg.TLSCertPath != "" && clientCfg.TLSKeyPath != "" {
		tlsConfig, err := createClientTLSConfig(
			clientCfg.TLSCertPath,
			clientCfg.TLSKeyPath,
			clientCfg.TLSCACertPath,
			clientCfg.DisableTLSVerify,
		)
		if err != nil {
			return fmt.Errorf("failed to create client TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		log.Warn().Msg("Using insecure connection to upstream Flight service")
	}

	// Create the connection to the upstream Flight service
	upstreamAddr := fmt.Sprintf("%s:%d", clientCfg.UpstreamHost, clientCfg.UpstreamPort)

	// Create the Flight client using the non-deprecated method
	var err error
	s.upstreamClient, err = flight.NewClientWithMiddleware(upstreamAddr, nil, []flight.ClientMiddleware{}, opts...)
	if err != nil {
		return fmt.Errorf("failed to create upstream Flight client: %w", err)
	}

	log.Info().Str("upstream", upstreamAddr).Msg("Connected to upstream Flight service")
	return nil
}

// Start starts the Flight server
func (s *SecureFlightServer) Start() error {
	if !s.initialized {
		return fmt.Errorf("server not properly initialized")
	}

	// Set up server options
	var serverOpts []grpc.ServerOption

	// Set up TLS if configured
	if s.cfg.Server.TLSCertPath != "" && s.cfg.Server.TLSKeyPath != "" {
		tlsConfig, err := createServerTLSConfig(
			s.cfg.Server.TLSCertPath,
			s.cfg.Server.TLSKeyPath,
			s.cfg.Server.TLSCACertPath,
			s.cfg.Server.EnableMTLS,
		)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		log.Warn().Msg("TLS is not configured, using insecure server")
	}

	// Create and register the secure flight service
	svc := &secureFlightService{
		BaseFlightServer: &flight.BaseFlightServer{},
		server:           s,
	}

	// Create the gRPC server
	s.grpcServer = grpc.NewServer(serverOpts...)

	// Register the service with the server
	flight.RegisterFlightServiceServer(s.grpcServer, svc)

	// Start the server
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Info().Str("addr", addr).Msg("Starting Secure Flight Gateway")
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			log.Error().Err(err).Msg("Failed to start Flight server")
		}
	}()

	return nil
}

// Stop stops the Flight server
func (s *SecureFlightServer) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	log.Info().Msg("Secure Flight Gateway stopped")
}

// createServerTLSConfig creates a TLS configuration for the server
func createServerTLSConfig(certPath, keyPath, caPath string, enableMTLS bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if enableMTLS && caPath != "" {
		// Load CA certificate for client authentication
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to append CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		log.Info().Msg("mTLS enabled for server")
	}

	return tlsConfig, nil
}

// createClientTLSConfig creates a TLS configuration for the client
func createClientTLSConfig(certPath, keyPath, caPath string, skipVerify bool) (*tls.Config, error) {
	var certificates []tls.Certificate

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
		}
		certificates = append(certificates, cert)
	}

	tlsConfig := &tls.Config{
		Certificates:       certificates,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify,
	}

	if caPath != "" {
		// Load CA certificate for server verification
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to append CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// secureFlightService implements the Flight service interface
type secureFlightService struct {
	*flight.BaseFlightServer
	server *SecureFlightServer
}

// Handshake handles the handshake protocol
func (s *secureFlightService) Handshake(stream flight.FlightService_HandshakeServer) error {
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
func (s *secureFlightService) ListFlights(criteria *flight.Criteria, stream flight.FlightService_ListFlightsServer) error {
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

// GetFlightInfo gets info about a flight
func (s *secureFlightService) GetFlightInfo(ctx context.Context, request *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	log.Debug().Msg("GetFlightInfo request received")

	// Apply security checks to the request
	// In a real implementation, we'd verify the request is valid and authorized

	// Pass through to the upstream service
	if s.server.upstreamClient != nil {
		info, err := s.server.upstreamClient.GetFlightInfo(ctx, request)
		if err != nil {
			return nil, err
		}

		// Apply additional security checks to the result
		// In a real implementation, we'd verify the info is valid

		return info, nil
	}

	return nil, fmt.Errorf("no upstream Flight service configured")
}

// GetSchema gets the schema of a flight
func (s *secureFlightService) GetSchema(ctx context.Context, request *flight.FlightDescriptor) (*flight.SchemaResult, error) {
	log.Debug().Msg("GetSchema request received")

	// Apply schema validation
	// In a real implementation, we'd verify the schema meets security requirements

	// Pass through to the upstream service
	if s.server.upstreamClient != nil {
		schema, err := s.server.upstreamClient.GetSchema(ctx, request)
		if err != nil {
			return nil, err
		}

		// Additional schema validation could be applied here

		return schema, nil
	}

	return nil, fmt.Errorf("no upstream Flight service configured")
}

// DoGet performs a flight data get operation
func (s *secureFlightService) DoGet(ticket *flight.Ticket, stream flight.FlightService_DoGetServer) error {
	log.Debug().Msg("DoGet request received")
	ctx := stream.Context()

	// Verify ticket authenticity if HMAC verification is enabled
	if s.server.hmacVerifier != nil && len(ticket.Ticket) > 0 {
		hmacValid, err := s.server.hmacVerifier.VerifyHMAC(ticket.Ticket, []byte("flight-ticket"))
		if err != nil {
			log.Error().Err(err).Msg("Failed to verify ticket HMAC")
			return fmt.Errorf("failed to verify ticket: %w", err)
		}
		if !hmacValid {
			log.Warn().Msg("Invalid ticket HMAC signature")
			return fmt.Errorf("invalid ticket signature")
		}
	}

	// Pass through to the upstream service
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.DoGet(ctx, ticket)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get data from upstream")
			return err
		}

		// Stream data back to the client
		_ = -1 // Initialize lastSequenceNumber for use in real implementation
		for {
			data, err := upstreamStream.Recv()
			if err != nil {
				return err
			}

			// Apply security verification

			// HMAC verification example (commented out for now)
			// if s.server.hmacVerifier != nil && data.AppMetadata != nil {
			//     // Extract HMAC from metadata in a real implementation
			//     hmacValid, err := s.server.hmacVerifier.VerifyHMAC(hmacBytes, data.DataBody)
			//     if err != nil {
			//         return fmt.Errorf("failed to verify HMAC: %w", err)
			//     }
			//     if !hmacValid {
			//         return fmt.Errorf("invalid HMAC")
			//     }
			// }

			// Merkle verification example (commented out for now)
			// if s.server.merkleVerifier != nil {
			//     // Extract merkle proof and sequence info in a real implementation
			//     valid, err := s.server.merkleVerifier.VerifyStreamProof(
			//         merkleProof, data.DataBody, sequence, isLastChunk)
			//     if err != nil {
			//         return fmt.Errorf("failed to verify merkle proof: %w", err)
			//     }
			//     if !valid {
			//         return fmt.Errorf("invalid merkle proof")
			//     }
			//
			//     // Verify sequence for anti-replay
			//     if sequence <= lastSequenceNumber {
			//         return fmt.Errorf("invalid sequence (potential replay attack)")
			//     }
			//     lastSequenceNumber = sequence
			// }

			// Send data to client
			if err := stream.Send(data); err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("no upstream Flight service configured")
}

// DoPut performs a flight data put operation
func (s *secureFlightService) DoPut(stream flight.FlightService_DoPutServer) error {
	log.Debug().Msg("DoPut request received")
	ctx := stream.Context()

	// Pass through to the upstream service with security verification
	if s.server.upstreamClient != nil {
		upstreamStream, err := s.server.upstreamClient.DoPut(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to put data to upstream")
			return err
		}

		var schema *arrow.Schema
		putDone := make(chan struct{})
		errorCh := make(chan error, 2)

		// Stream data to the upstream service
		go func() {
			_ = -1 // lastSequenceNumber for use in real implementation

			for {
				chunk, err := stream.Recv()
				if err != nil {
					errorCh <- err
					close(putDone)
					return
				}

				// Apply security verification

				// Example HMAC verification (commented out for now)
				// if s.server.hmacVerifier != nil && chunk.AppMetadata != nil {
				//     // Extract HMAC from metadata
				//     hmacValid, err := s.server.hmacVerifier.VerifyHMAC(hmacBytes, chunk.DataBody)
				//     if err != nil {
				//         errorCh <- fmt.Errorf("failed to verify HMAC: %w", err)
				//         close(putDone)
				//         return
				//     }
				//     if !hmacValid {
				//         errorCh <- fmt.Errorf("invalid HMAC")
				//         close(putDone)
				//         return
				//     }
				// }

				// Example attestation verification (commented out for now)
				// if s.server.attestationVerifier != nil {
				//     // Extract attestation from metadata
				//     attestValid, err := s.server.attestationVerifier.VerifyAttestation(
				//         attestation, publicKey, chunk.DataBody)
				//     if err != nil {
				//         errorCh <- fmt.Errorf("failed to verify attestation: %w", err)
				//         close(putDone)
				//         return
				//     }
				//     if !attestValid {
				//         errorCh <- fmt.Errorf("invalid attestation")
				//         close(putDone)
				//         return
				//     }
				// }

				// Send to upstream
				if err := upstreamStream.Send(chunk); err != nil {
					errorCh <- err
					close(putDone)
					return
				}

				// For the first chunk, save the schema
				if schema == nil && chunk.GetDataHeader() != nil {
					schema, err = flight.DeserializeSchema(chunk.GetDataHeader(), nil)
					if err != nil {
						log.Error().Err(err).Msg("Failed to deserialize schema")
					}
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

				if err := stream.Send(result); err != nil {
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
			return err
		}
	}

	return fmt.Errorf("no upstream Flight service configured")
}

// DoExchange performs bidirectional data exchange
func (s *secureFlightService) DoExchange(stream flight.FlightService_DoExchangeServer) error {
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
func (s *secureFlightService) DoAction(action *flight.Action, stream flight.FlightService_DoActionServer) error {
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
func (s *secureFlightService) ListActions(empty *flight.Empty, stream flight.FlightService_ListActionsServer) error {
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
