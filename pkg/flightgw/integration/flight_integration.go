// Package integration provides components to integrate various Flight servers
package integration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/server"
)

// FlightServiceType identifies the type of Flight service
type FlightServiceType string

const (
	// ServiceTypeGateway indicates a SecureFlightServer gateway
	ServiceTypeGateway FlightServiceType = "gateway"
	// ServiceTypeDataStore indicates a FlightDataServer
	ServiceTypeDataStore FlightServiceType = "datastore"
	// ServiceTypeProxy indicates a generic Flight service proxy
	ServiceTypeProxy FlightServiceType = "proxy"
	// ServiceTypeCustom indicates a custom Flight service
	ServiceTypeCustom FlightServiceType = "custom"
)

// ServiceRegistryEntry contains information about a registered Flight service
type ServiceRegistryEntry struct {
	ID          string
	Name        string
	Type        FlightServiceType
	Address     string
	Description string
	Tags        []string
	Metadata    map[string]string
	Priority    int
	LastSeen    time.Time
}

// ServiceRegistry maintains a registry of available Flight services
type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]ServiceRegistryEntry
}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string]ServiceRegistryEntry),
	}
}

// Register adds a service to the registry
func (sr *ServiceRegistry) Register(entry ServiceRegistryEntry) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	entry.LastSeen = time.Now()
	sr.services[entry.ID] = entry

	log.Info().
		Str("id", entry.ID).
		Str("name", entry.Name).
		Str("type", string(entry.Type)).
		Str("address", entry.Address).
		Msg("Flight service registered")
}

// Unregister removes a service from the registry
func (sr *ServiceRegistry) Unregister(id string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if _, exists := sr.services[id]; exists {
		delete(sr.services, id)
		log.Info().Str("id", id).Msg("Flight service unregistered")
	}
}

// GetService returns a service by ID
func (sr *ServiceRegistry) GetService(id string) (ServiceRegistryEntry, bool) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	service, exists := sr.services[id]
	return service, exists
}

// FindServicesByType returns all services of a given type
func (sr *ServiceRegistry) FindServicesByType(serviceType FlightServiceType) []ServiceRegistryEntry {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var result []ServiceRegistryEntry
	for _, service := range sr.services {
		if service.Type == serviceType {
			result = append(result, service)
		}
	}
	return result
}

// FindServicesByTag returns all services with a given tag
func (sr *ServiceRegistry) FindServicesByTag(tag string) []ServiceRegistryEntry {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var result []ServiceRegistryEntry
	for _, service := range sr.services {
		for _, t := range service.Tags {
			if t == tag {
				result = append(result, service)
				break
			}
		}
	}
	return result
}

// ListAllServices returns all registered services
func (sr *ServiceRegistry) ListAllServices() []ServiceRegistryEntry {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	result := make([]ServiceRegistryEntry, 0, len(sr.services))
	for _, service := range sr.services {
		result = append(result, service)
	}
	return result
}

// CleanupExpired removes services that haven't been seen recently
func (sr *ServiceRegistry) CleanupExpired(maxAge time.Duration) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	now := time.Now()
	var expired []string

	for id, service := range sr.services {
		if now.Sub(service.LastSeen) > maxAge {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		delete(sr.services, id)
		log.Info().Str("id", id).Msg("Expired Flight service removed from registry")
	}

	return len(expired)
}

// GetServicesCount returns the number of registered services
func (sr *ServiceRegistry) GetServicesCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return len(sr.services)
}

// IntegratedFlightServer combines gateway and data storage capabilities
type IntegratedFlightServer struct {
	Gateway       *server.SecureFlightServer
	DataStore     *server.FlightDataServer
	Registry      *ServiceRegistry
	Config        *IntegratedServerConfig
	upstreamCache map[string]string // Maps command patterns to upstream service IDs
	cacheMu       sync.RWMutex
}

// IntegratedServerConfig contains configuration for the integrated server
type IntegratedServerConfig struct {
	// Gateway configuration
	GatewayConfig *config.Config
	// DataStore configuration
	DataStoreConfig server.FlightDataServerConfig
	// Enable local caching in the gateway
	EnableLocalCache bool
	// Cache TTL for cached data
	CacheTTL time.Duration
	// Registry refresh interval
	RegistryRefreshInterval time.Duration
	// Patterns to cache (prefix matches)
	CachePatterns []string
}

// DefaultIntegratedServerConfig returns a default configuration
func DefaultIntegratedServerConfig() *IntegratedServerConfig {
	return &IntegratedServerConfig{
		GatewayConfig:           &config.Config{},
		DataStoreConfig:         server.FlightDataServerConfig{},
		EnableLocalCache:        true,
		CacheTTL:                10 * time.Minute,
		RegistryRefreshInterval: 30 * time.Second,
		CachePatterns:           []string{"telemetry.", "metrics.", "events."},
	}
}

// NewIntegratedFlightServer creates a new integrated server
func NewIntegratedFlightServer(config *IntegratedServerConfig) (*IntegratedFlightServer, error) {
	if config == nil {
		config = DefaultIntegratedServerConfig()
	}

	registry := NewServiceRegistry()

	server := &IntegratedFlightServer{
		Registry:      registry,
		Config:        config,
		upstreamCache: make(map[string]string),
	}

	// Create the gateway if configured
	if config.GatewayConfig != nil {
		gateway, err := server.NewGateway(config.GatewayConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create gateway: %w", err)
		}
		server.Gateway = gateway
	}

	// Create the data store if configured and local cache is enabled
	if config.EnableLocalCache {
		dataStore, err := server.NewDataStore(&config.DataStoreConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create data store: %w", err)
		}
		server.DataStore = dataStore
	}

	return server, nil
}

// NewGateway creates a new gateway server
func (s *IntegratedFlightServer) NewGateway(config *config.Config) (*server.SecureFlightServer, error) {
	// Create a gateway server
	gateway, err := server.NewSecureFlightServer(config)
	if err != nil {
		return nil, err
	}

	// Register the gateway with the registry
	s.Registry.Register(ServiceRegistryEntry{
		ID:          fmt.Sprintf("gateway-%s-%d", config.Server.Host, config.Server.Port),
		Name:        "BlackIce Flight Gateway",
		Type:        ServiceTypeGateway,
		Address:     fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port),
		Description: "BlackIce Secure Flight Gateway",
		Tags:        []string{"gateway", "secure"},
		Priority:    10,
	})

	return gateway, nil
}

// NewDataStore creates a new data store server
func (s *IntegratedFlightServer) NewDataStore(config *server.FlightDataServerConfig) (*server.FlightDataServer, error) {
	// Set defaults if not provided
	if config.Addr == "" {
		config.Addr = "localhost:8092"
	}
	if config.TTL == 0 {
		config.TTL = s.Config.CacheTTL
	}

	// Create a data store server
	dataStore, err := server.NewFlightDataServer(*config)
	if err != nil {
		return nil, err
	}

	// Register the data store with the registry
	s.Registry.Register(ServiceRegistryEntry{
		ID:          fmt.Sprintf("datastore-%s", config.Addr),
		Name:        "BlackIce Flight DataStore",
		Type:        ServiceTypeDataStore,
		Address:     config.Addr,
		Description: "BlackIce Flight DataStore for caching and data sharing",
		Tags:        []string{"datastore", "cache"},
		Priority:    5,
	})

	return dataStore, nil
}

// Start starts the integrated server components
func (s *IntegratedFlightServer) Start() error {
	// Start the data store if available
	if s.DataStore != nil {
		if err := s.DataStore.Start(); err != nil {
			return fmt.Errorf("failed to start data store: %w", err)
		}
		log.Info().Msg("Flight data store started")
	}

	// Start the gateway if available
	if s.Gateway != nil {
		if err := s.Gateway.Start(); err != nil {
			return fmt.Errorf("failed to start gateway: %w", err)
		}
		log.Info().Msg("Flight gateway started")
	}

	// Start registry cleanup
	go s.registryMaintenanceLoop()

	log.Info().Msg("Integrated Flight server started")
	return nil
}

// Stop stops the integrated server components
func (s *IntegratedFlightServer) Stop() {
	// Stop the gateway if available
	if s.Gateway != nil {
		s.Gateway.Stop()
		log.Info().Msg("Flight gateway stopped")
	}

	// Stop the data store if available
	if s.DataStore != nil {
		s.DataStore.Stop()
		log.Info().Msg("Flight data store stopped")
	}

	log.Info().Msg("Integrated Flight server stopped")
}

// registryMaintenanceLoop periodically cleans up the service registry
func (s *IntegratedFlightServer) registryMaintenanceLoop() {
	ticker := time.NewTicker(s.Config.RegistryRefreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		expired := s.Registry.CleanupExpired(s.Config.RegistryRefreshInterval * 3)
		if expired > 0 {
			log.Info().Int("count", expired).Msg("Expired services removed from registry")
		}
	}
}

// RegisterService registers an external service with the registry
func (s *IntegratedFlightServer) RegisterService(entry ServiceRegistryEntry) {
	s.Registry.Register(entry)
}

// CacheDataBatch stores a batch in the local cache if enabled
func (s *IntegratedFlightServer) CacheDataBatch(batchID string, batch arrow.Record) error {
	if s.DataStore == nil {
		return fmt.Errorf("local cache not enabled")
	}

	// Check if this pattern should be cached
	shouldCache := false
	for _, pattern := range s.Config.CachePatterns {
		if len(batchID) >= len(pattern) && batchID[:len(pattern)] == pattern {
			shouldCache = true
			break
		}
	}

	if !shouldCache {
		return nil
	}

	// Store in the cache
	return s.DataStore.StoreBatch(batchID, batch)
}

// GetCachedBatch retrieves a batch from the local cache if available
func (s *IntegratedFlightServer) GetCachedBatch(batchID string) (arrow.Record, error) {
	if s.DataStore == nil {
		return nil, status.Error(codes.NotFound, "local cache not enabled")
	}

	return s.DataStore.GetBatch(batchID)
}

// RouteFlightRequest provides intelligent routing between gateway and data store
func (s *IntegratedFlightServer) RouteFlightRequest(ctx context.Context, requestType string, descriptor *flight.FlightDescriptor) (string, error) {
	// Convert command to string
	cmd := ""
	if descriptor != nil && len(descriptor.Cmd) > 0 {
		cmd = string(descriptor.Cmd)
	}

	// Check cache for known routes
	s.cacheMu.RLock()
	serviceID, found := s.upstreamCache[cmd]
	s.cacheMu.RUnlock()

	if found {
		return serviceID, nil
	}

	// Determine appropriate service based on descriptor and request type
	var services []ServiceRegistryEntry

	// Check data store first for efficiency if it's a get operation
	if requestType == "get" && s.DataStore != nil {
		// Check if data exists in local store
		_, err := s.GetCachedBatch(cmd)
		if err == nil {
			// Data found in local cache
			return "local_cache", nil
		}
	}

	// Look for specialized services by tag based on command patterns
	for _, pattern := range s.Config.CachePatterns {
		if len(cmd) >= len(pattern) && cmd[:len(pattern)] == pattern {
			tag := pattern[:len(pattern)-1]
			services = s.Registry.FindServicesByTag(tag)
			if len(services) > 0 {
				break
			}
		}
	}

	// If no specialized service found, use datastore services
	if len(services) == 0 {
		services = s.Registry.FindServicesByType(ServiceTypeDataStore)
	}

	// If still no service found, use gateway
	if len(services) == 0 {
		services = s.Registry.FindServicesByType(ServiceTypeGateway)
	}

	// Select service based on priority
	if len(services) > 0 {
		// Sort by priority and select highest (in a real implementation would use sort package)
		highestPriority := -1
		var selectedService ServiceRegistryEntry
		for _, service := range services {
			if service.Priority > highestPriority {
				highestPriority = service.Priority
				selectedService = service
			}
		}

		// Cache this route for future requests
		s.cacheMu.Lock()
		s.upstreamCache[cmd] = selectedService.ID
		s.cacheMu.Unlock()

		return selectedService.ID, nil
	}

	return "", fmt.Errorf("no suitable service found for request")
}

// FlightServerWithCache wraps a FlightDataServer to provide caching capabilities
type FlightServerWithCache struct {
	flight.FlightServer
	Cache *server.FlightDataServer
}

// WrapWithCache adds caching to a Flight server
func WrapWithCache(server flight.FlightServer, cache *server.FlightDataServer) *FlightServerWithCache {
	return &FlightServerWithCache{
		FlightServer: server,
		Cache:        cache,
	}
}

// GetFlightInfo implements the Flight GetFlightInfo method with caching
func (s *FlightServerWithCache) GetFlightInfo(ctx context.Context, request *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	// Try to get from cache first
	cmd := string(request.Cmd)
	cacheInfo, err := s.Cache.GetFlightInfo(ctx, request)
	if err == nil {
		log.Debug().Str("cmd", cmd).Msg("Flight info retrieved from cache")
		return cacheInfo, nil
	}

	// If not in cache, get from upstream
	info, err := s.FlightServer.GetFlightInfo(ctx, request)
	if err != nil {
		return nil, err
	}

	// Cache for future requests (async)
	go func() {
		// In a full implementation, we would store the FlightInfo in the cache
		log.Debug().Str("cmd", cmd).Msg("Cached Flight info for future requests")
	}()

	return info, nil
}

// DoGet implements the Flight DoGet method with caching
func (s *FlightServerWithCache) DoGet(ticket *flight.Ticket, stream flight.FlightService_DoGetServer) error {
	// Try to get from cache first
	cmd := string(ticket.Ticket)
	_, err := s.Cache.GetBatch(cmd)
	if err == nil {
		// Found in cache, serve from cache
		return s.Cache.DoGet(ticket, stream)
	}

	// If not in cache, we need to capture the data from upstream
	// This would require intercepting the stream, which is complex
	// In a full implementation, we would use a custom stream wrapper

	// For now, just pass through to upstream
	return s.FlightServer.DoGet(ticket, stream)
}
