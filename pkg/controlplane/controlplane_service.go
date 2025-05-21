package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/controlplane/auth"
	"github.com/TFMV/blackice/pkg/controlplane/config"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// ControlPlaneService implements the ControlPlaneService gRPC interface
type ControlPlaneService struct {
	blackicev1.UnimplementedControlPlaneServiceServer

	config            *config.ControlPlaneConfig
	authService       *auth.AuthService
	componentCache    map[string]*blackicev1.SystemComponent
	componentsMutex   sync.RWMutex
	registeredClients map[string]ServiceClient
}

// ServiceClient defines the interface for communicating with other BlackIce services
type ServiceClient interface {
	GetStatus(ctx context.Context) (*blackicev1.NodeHealth, error)
	ExecuteCommand(ctx context.Context, command string, params []byte) ([]byte, error)
}

// NewControlPlaneService creates a new Control Plane service
func NewControlPlaneService(
	cfg *config.ControlPlaneConfig,
	authService *auth.AuthService,
) *ControlPlaneService {
	service := &ControlPlaneService{
		config:            cfg,
		authService:       authService,
		componentCache:    make(map[string]*blackicev1.SystemComponent),
		registeredClients: make(map[string]ServiceClient),
	}

	// Start background tasks
	go service.startComponentHealthChecker()

	return service
}

// GetSystemStatus retrieves status information for all system components
func (s *ControlPlaneService) GetSystemStatus(ctx context.Context, req *blackicev1.GetSystemStatusRequest) (*blackicev1.SystemStatusResponse, error) {
	// Create a response with the current status of components
	resp := &blackicev1.SystemStatusResponse{
		Status: &blackicev1.Status{
			Code: blackicev1.Status_OK,
		},
		Components:   make([]*blackicev1.SystemComponent, 0),
		ActiveAlerts: make(map[string]*blackicev1.AlertSummary),
		Resources:    &blackicev1.SystemResourceSummary{},
	}

	// Get component list based on filters in the request
	s.componentsMutex.RLock()
	defer s.componentsMutex.RUnlock()

	for _, component := range s.componentCache {
		// Apply filters if specified
		if len(req.ComponentIds) > 0 {
			found := false
			for _, id := range req.ComponentIds {
				if component.ComponentId == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if len(req.ComponentTypes) > 0 {
			found := false
			for _, compType := range req.ComponentTypes {
				if component.ComponentType == compType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Add component to response
		resp.Components = append(resp.Components, component)

		// Gather resource metrics
		if metrics := component.Health.GetMetrics(); metrics != nil {
			if cpuStr, ok := metrics["cpu_usage"]; ok {
				var cpu float64
				if _, err := fmt.Sscanf(cpuStr, "%f", &cpu); err == nil {
					resp.Resources.CpuUsagePercent += cpu
				}
			}

			if memStr, ok := metrics["memory_usage"]; ok {
				var mem float64
				if _, err := fmt.Sscanf(memStr, "%f", &mem); err == nil {
					resp.Resources.MemoryUsagePercent += mem
				}
			}

			if storageStr, ok := metrics["storage_usage"]; ok {
				var storage float64
				if _, err := fmt.Sscanf(storageStr, "%f", &storage); err == nil {
					resp.Resources.StorageUsagePercent += storage
				}
			}

			if connsStr, ok := metrics["active_connections"]; ok {
				var conns int64
				if _, err := fmt.Sscanf(connsStr, "%d", &conns); err == nil {
					resp.Resources.TotalActiveConnections += conns
				}
			}

			if epsStr, ok := metrics["events_per_second"]; ok {
				var eps int64
				if _, err := fmt.Sscanf(epsStr, "%d", &eps); err == nil {
					resp.Resources.TotalEventsPerSecond += eps
				}
			}
		}
	}

	// Average metrics across components
	componentCount := float64(len(resp.Components))
	if componentCount > 0 {
		resp.Resources.CpuUsagePercent /= componentCount
		resp.Resources.MemoryUsagePercent /= componentCount
		resp.Resources.StorageUsagePercent /= componentCount
	}

	return resp, nil
}

// ManageConfiguration handles updates to system configuration
func (s *ControlPlaneService) ManageConfiguration(ctx context.Context, req *blackicev1.ManageConfigurationRequest) (*blackicev1.ConfigurationResponse, error) {
	// Verify attestation
	// In a real implementation, this would verify the admin's attestation

	// Find the component
	componentID := req.ComponentId
	client, exists := s.registeredClients[componentID]
	if !exists {
		return &blackicev1.ConfigurationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_NOT_FOUND,
				Message: "component not found",
			},
		}, status.Error(codes.NotFound, "component not found")
	}

	// Execute a configuration update command on the component
	// This is a placeholder for actual implementation
	configOp := "UPDATE"
	if req.GetResetToDefault() {
		configOp = "RESET"
	}

	cmdParams, err := encodeConfigCommand(configOp, req.ConfigSection, req.GetUpdateConfigJson())
	if err != nil {
		return &blackicev1.ConfigurationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INVALID_INPUT,
				Message: "invalid configuration parameters",
			},
		}, status.Error(codes.InvalidArgument, "invalid configuration parameters")
	}

	// Execute the command on the target component
	_, err = client.ExecuteCommand(ctx, "CONFIG", cmdParams)
	if err != nil {
		return &blackicev1.ConfigurationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_ERROR,
				Message: fmt.Sprintf("failed to update configuration: %v", err),
			},
		}, status.Error(codes.Internal, "failed to update configuration")
	}

	// Create a ledger entry for the configuration change
	// This is a placeholder for actual implementation
	ledgerEntry := &blackicev1.LedgerEntry{
		EntryId:           generateUniqueID(),
		CommittedAtUnixNs: time.Now().UnixNano(),
		EntryType:         blackicev1.EntryType_CONFIGURATION_CHANGE,
	}

	return &blackicev1.ConfigurationResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "configuration updated successfully",
		},
		OperationId:             generateUniqueID(),
		LedgerEntryConfirmation: ledgerEntry,
	}, nil
}

// ListComponents returns information on all registered system components
func (s *ControlPlaneService) ListComponents(ctx context.Context, req *blackicev1.ListComponentsRequest) (*blackicev1.ListComponentsResponse, error) {
	s.componentsMutex.RLock()
	defer s.componentsMutex.RUnlock()

	// Apply filters
	filteredComponents := make([]*blackicev1.SystemComponent, 0)
	for _, component := range s.componentCache {
		// Filter by component types if specified
		if len(req.ComponentTypes) > 0 {
			found := false
			for _, compType := range req.ComponentTypes {
				if component.ComponentType == compType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Add component to filtered list
		if req.IncludeHealth {
			// Include the health data
			filteredComponents = append(filteredComponents, component)
		} else {
			// Create a copy without health data to reduce response size
			// Using a new object and copying only the non-mutex fields to avoid copying lock values
			componentCopy := &blackicev1.SystemComponent{
				ComponentId:         component.ComponentId,
				ComponentType:       component.ComponentType,
				Version:             component.Version,
				LastHeartbeatUnixNs: component.LastHeartbeatUnixNs,
				// Explicitly not copying Health to reduce response size
			}
			filteredComponents = append(filteredComponents, componentCopy)
		}
	}

	// Apply pagination
	pageSize := 50 // Default page size
	if req.PageSize > 0 {
		pageSize = int(req.PageSize)
	}

	startIndex := 0
	// Note: PageToken handling is a placeholder for now
	// In a real implementation, the token would be decoded to get the start index
	// For example, a base64 encoded JSON object with pagination details

	endIndex := startIndex + pageSize
	if endIndex > len(filteredComponents) {
		endIndex = len(filteredComponents)
	}

	// Get the components for this page
	pagedComponents := filteredComponents[startIndex:endIndex]

	// Create a next page token if there are more components
	var nextPageToken string
	if endIndex < len(filteredComponents) {
		nextPageToken = fmt.Sprintf("%d", endIndex)
	}

	return &blackicev1.ListComponentsResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "components retrieved successfully",
		},
		Components:    pagedComponents,
		NextPageToken: nextPageToken,
	}, nil
}

// GetAuditHistory retrieves audit logs with filtering and pagination
func (s *ControlPlaneService) GetAuditHistory(ctx context.Context, req *blackicev1.GetAuditHistoryRequest) (*blackicev1.GetAuditHistoryResponse, error) {
	// In a real implementation, this would query an audit log storage system
	// For now, we'll return a placeholder response

	return &blackicev1.GetAuditHistoryResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "audit logs retrieved successfully",
		},
		AuditLogs:     make([]*blackicev1.AuditLogEntry, 0),
		NextPageToken: "",
	}, nil
}

// ExecuteControlCommand executes an administrative command on a component
func (s *ControlPlaneService) ExecuteControlCommand(ctx context.Context, req *blackicev1.ExecuteControlCommandRequest) (*blackicev1.ExecuteControlCommandResponse, error) {
	// Verify attestation
	// In a real implementation, this would verify the admin's attestation

	// Find the component
	componentID := req.ComponentId
	client, exists := s.registeredClients[componentID]
	if !exists {
		return &blackicev1.ExecuteControlCommandResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_NOT_FOUND,
				Message: "component not found",
			},
		}, status.Error(codes.NotFound, "component not found")
	}

	// Execute the command
	result, err := client.ExecuteCommand(ctx, req.Command, req.CommandParameters)
	if err != nil {
		return &blackicev1.ExecuteControlCommandResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_ERROR,
				Message: fmt.Sprintf("command execution failed: %v", err),
			},
		}, status.Error(codes.Internal, "command execution failed")
	}

	// Create a ledger entry for the command execution
	ledgerEntry := &blackicev1.LedgerEntry{
		EntryId:           generateUniqueID(),
		CommittedAtUnixNs: time.Now().UnixNano(),
	}

	return &blackicev1.ExecuteControlCommandResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "command executed successfully",
		},
		Result:                  result,
		OperationId:             generateUniqueID(),
		LedgerEntryConfirmation: ledgerEntry,
	}, nil
}

// RegisterComponent registers a new component with the control plane
// This would be called by other services to register themselves
func (s *ControlPlaneService) RegisterComponent(component *blackicev1.SystemComponent, client ServiceClient) {
	s.componentsMutex.Lock()
	defer s.componentsMutex.Unlock()

	s.componentCache[component.ComponentId] = component
	s.registeredClients[component.ComponentId] = client
}

// UpdateComponentHealth updates the health status of a registered component
func (s *ControlPlaneService) UpdateComponentHealth(componentID string, health *blackicev1.NodeHealth) error {
	s.componentsMutex.Lock()
	defer s.componentsMutex.Unlock()

	component, exists := s.componentCache[componentID]
	if !exists {
		return fmt.Errorf("component %s not registered", componentID)
	}

	component.Health = health
	component.LastHeartbeatUnixNs = time.Now().UnixNano()

	return nil
}

// startComponentHealthChecker runs a background task to check component health
func (s *ControlPlaneService) startComponentHealthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.checkComponentHealth()
	}
}

// checkComponentHealth checks the health of all registered components
func (s *ControlPlaneService) checkComponentHealth() {
	s.componentsMutex.Lock()
	defer s.componentsMutex.Unlock()

	now := time.Now().UnixNano()

	for id, component := range s.componentCache {
		// Check the last heartbeat timestamp
		lastHeartbeat := component.LastHeartbeatUnixNs
		if now-lastHeartbeat > 60*1000*1000*1000 { // 60 seconds in nanoseconds
			// Component hasn't sent a heartbeat in too long
			if component.Health == nil {
				component.Health = &blackicev1.NodeHealth{}
			}
			component.Health.State = blackicev1.NodeHealth_DEGRADED

			// In a real implementation, we would trigger alerts and recovery actions
		}

		// Poll the component for its current status
		client, exists := s.registeredClients[id]
		if exists {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			health, err := client.GetStatus(ctx)
			if err == nil && health != nil {
				// Update the component health
				component.Health = health
				component.LastHeartbeatUnixNs = now
			}
		}
	}
}

// Helper functions

// encodeConfigCommand encodes a configuration command and its parameters
func encodeConfigCommand(operation, section string, configData []byte) ([]byte, error) {
	// Create a structured format for the command and parameters
	type ConfigCommand struct {
		Operation  string          `json:"operation"`
		Section    string          `json:"section"`
		ConfigData json.RawMessage `json:"config_data,omitempty"`
		Timestamp  int64           `json:"timestamp"`
		CommandID  string          `json:"command_id"`
	}

	// Generate a unique command ID
	commandID := fmt.Sprintf("config-%d", time.Now().UnixNano())

	// Create the command structure
	cmd := ConfigCommand{
		Operation: operation,
		Section:   section,
		Timestamp: time.Now().UnixNano(),
		CommandID: commandID,
	}

	// Only include config data if it's not empty
	if len(configData) > 0 {
		// Validate that the config data is valid JSON
		var js json.RawMessage
		if err := json.Unmarshal(configData, &js); err != nil {
			return nil, fmt.Errorf("invalid JSON in config data: %w", err)
		}
		cmd.ConfigData = js
	}

	// Marshal the command to JSON
	encodedCmd, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to encode config command: %w", err)
	}

	return encodedCmd, nil
}

// generateUniqueID generates a unique identifier
func generateUniqueID() string {
	return fmt.Sprintf("cp-%d", time.Now().UnixNano())
}
