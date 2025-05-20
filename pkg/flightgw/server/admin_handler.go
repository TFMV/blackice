package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// AdminHandler handles admin API requests
type AdminHandler struct {
	server *SecureFlightServer
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(server *SecureFlightServer) *AdminHandler {
	return &AdminHandler{
		server: server,
	}
}

// StartAdminAPI starts the admin API endpoint
func (s *SecureFlightServer) StartAdminAPI() error {
	if s.cfg.Proxy.AdminAPIEnabled {
		adminHandler := NewAdminHandler(s)

		// Create HTTP mux for admin API
		mux := http.NewServeMux()

		// Policy management endpoints
		mux.HandleFunc("/api/policies", adminHandler.handlePolicies)
		mux.HandleFunc("/api/policies/", adminHandler.handlePolicy)

		// Circuit breaker management
		mux.HandleFunc("/api/circuit-breaker", adminHandler.handleCircuitBreaker)

		// Start the admin API server in the background
		addr := s.cfg.Proxy.AdminAPIAddr
		if addr == "" {
			addr = ":9091" // default to port 9091
		}

		adminServer := &http.Server{Addr: addr, Handler: mux}
		go func() {
			log.Info().Str("addr", addr).Msg("Starting admin API endpoint")
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("Admin API server failed")
			}
		}()
	} else {
		log.Info().Msg("Admin API disabled")
	}

	return nil
}

// handlePolicies handles requests to /api/policies
func (h *AdminHandler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listPolicies(w, r)
	case http.MethodPost:
		h.createPolicy(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePolicy handles requests to /api/policies/{name}
func (h *AdminHandler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	// Extract policy name from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	policyName := parts[len(parts)-1]

	switch r.Method {
	case http.MethodGet:
		h.getPolicy(w, r, policyName)
	case http.MethodPut:
		h.updatePolicy(w, r, policyName)
	case http.MethodDelete:
		h.deletePolicy(w, r, policyName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// listPolicies retrieves all policies
func (h *AdminHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	// Get policy type filter from query parameter
	policyType := r.URL.Query().Get("type")

	var policies []*Policy
	if policyType != "" {
		// Filter by type
		policies = h.server.policyManager.GetPoliciesByType(PolicyType(policyType))
	} else {
		// Get all policies
		pm := h.server.policyManager
		pm.mu.RLock()
		for _, p := range pm.policies {
			policies = append(policies, p)
		}
		pm.mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policies); err != nil {
		log.Error().Err(err).Msg("Failed to encode policies as JSON")
	}
}

// getPolicy retrieves a specific policy
func (h *AdminHandler) getPolicy(w http.ResponseWriter, r *http.Request, name string) {
	policy, exists := h.server.policyManager.GetPolicy(name)
	if !exists {
		http.Error(w, fmt.Sprintf("Policy %s not found", name), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policy); err != nil {
		log.Error().Err(err).Msg("Failed to encode policy as JSON")
	}
}

// createPolicy creates a new policy
func (h *AdminHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	var policy Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, fmt.Sprintf("Invalid policy JSON: %v", err), http.StatusBadRequest)
		return
	}

	if policy.Name == "" {
		http.Error(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	if err := h.server.policyManager.UpdatePolicy(&policy); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create policy: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(policy); err != nil {
		log.Error().Err(err).Msg("Failed to encode policy as JSON")
	}
}

// updatePolicy updates an existing policy
func (h *AdminHandler) updatePolicy(w http.ResponseWriter, r *http.Request, name string) {
	var policy Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, fmt.Sprintf("Invalid policy JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Ensure name in URL matches name in body
	if policy.Name != name {
		http.Error(w, "Policy name in URL must match policy name in request body", http.StatusBadRequest)
		return
	}

	if err := h.server.policyManager.UpdatePolicy(&policy); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update policy: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policy); err != nil {
		log.Error().Err(err).Msg("Failed to encode policy as JSON")
	}
}

// deletePolicy deletes a policy
func (h *AdminHandler) deletePolicy(w http.ResponseWriter, r *http.Request, name string) {
	if deleted := h.server.policyManager.DeletePolicy(name); !deleted {
		http.Error(w, fmt.Sprintf("Policy %s not found", name), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleCircuitBreaker handles requests to /api/circuit-breaker
func (h *AdminHandler) handleCircuitBreaker(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Get circuit breaker status
		status := map[string]interface{}{
			"state": fmt.Sprintf("%v", h.server.circuitBreaker.GetState()),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Error().Err(err).Msg("Failed to encode circuit breaker status as JSON")
		}

	case http.MethodPost:
		// Update circuit breaker state
		var req struct {
			Action string `json:"action"` // "open" or "close"
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}

		switch req.Action {
		case "open":
			h.server.circuitBreaker.ForceOpen()
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"status":"circuit opened"}`)); err != nil {
				log.Error().Err(err).Msg("Failed to write response")
			}
		case "close":
			h.server.circuitBreaker.ForceClose()
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"status":"circuit closed"}`)); err != nil {
				log.Error().Err(err).Msg("Failed to write response")
			}
		default:
			http.Error(w, "Invalid action, must be 'open' or 'close'", http.StatusBadRequest)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
