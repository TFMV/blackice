package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// AdminHandler provides HTTP handlers for admin operations
type AdminHandler struct {
	server *SecureFlightServer
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(server *SecureFlightServer) *AdminHandler {
	return &AdminHandler{
		server: server,
	}
}

// StartAdminAPI starts the admin HTTP API server
func (s *SecureFlightServer) StartAdminAPI() error {
	if s.adminServer != nil {
		return fmt.Errorf("admin API already running")
	}

	// Create admin handler
	adminHandler := NewAdminHandler(s)

	// Create HTTP mux for admin API
	mux := http.NewServeMux()

	// Circuit breaker endpoints
	mux.HandleFunc("/admin/circuit/state", adminHandler.handleCircuitState)
	mux.HandleFunc("/admin/circuit/force", adminHandler.handleCircuitForceState)
	mux.HandleFunc("/admin/circuit/tier", adminHandler.handleCircuitTier)
	mux.HandleFunc("/admin/circuit/metrics", adminHandler.handleCircuitMetrics)
	mux.HandleFunc("/admin/circuit/failures", adminHandler.handleCircuitFailures)
	mux.HandleFunc("/admin/circuit/recovery", adminHandler.handleCircuitRecovery)

	// Policy endpoints
	mux.HandleFunc("/admin/policies", adminHandler.handlePolicies)
	mux.HandleFunc("/admin/policies/reload", adminHandler.handlePolicyReload)

	// Start the admin server in the background
	addr := s.cfg.Proxy.AdminAPIAddr
	if addr == "" {
		addr = ":9091" // default to port 9091
	}
	s.adminServer = &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Info().Str("addr", addr).Msg("Starting admin API")
		if err := s.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Admin API server failed")
		}
	}()

	return nil
}

// handleCircuitState returns the current state of the circuit breaker
func (h *AdminHandler) handleCircuitState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := h.server.circuitBreaker.GetState()
	tier := h.server.circuitBreaker.GetTier()
	snapshot := h.server.circuitBreaker.Snapshot()

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"state":     fmt.Sprintf("%v", state),
		"tier":      fmt.Sprintf("%v", tier),
		"details":   snapshot,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode circuit state as JSON")
	}
}

// handleCircuitForceState forces the circuit breaker into a specific state
func (h *AdminHandler) handleCircuitForceState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the requested state from the URL query parameter
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	var message string
	switch stateParam {
	case "open":
		h.server.circuitBreaker.ForceOpen()
		message = "Circuit forced OPEN"
	case "closed":
		h.server.circuitBreaker.ForceClose()
		message = "Circuit forced CLOSED"
	default:
		http.Error(w, "Invalid state parameter (use 'open' or 'closed')", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":    "success",
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response as JSON")
	}
}

// handleCircuitTier sets the circuit breaker tier
func (h *AdminHandler) handleCircuitTier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the requested tier from the URL query parameter
	tierParam := r.URL.Query().Get("tier")
	if tierParam == "" {
		http.Error(w, "Missing tier parameter", http.StatusBadRequest)
		return
	}

	// Convert tier string to integer
	tierInt, err := strconv.Atoi(tierParam)
	if err != nil || tierInt < 0 || tierInt > 4 {
		http.Error(w, "Invalid tier parameter (use 0-4)", http.StatusBadRequest)
		return
	}

	h.server.circuitBreaker.SetTier(CircuitTier(tierInt))

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":    "success",
		"message":   fmt.Sprintf("Circuit tier set to %d", tierInt),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response as JSON")
	}
}

// handleCircuitMetrics returns detailed metrics from the circuit breaker
func (h *AdminHandler) handleCircuitMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := h.server.circuitBreaker.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode circuit metrics as JSON")
	}
}

// handleCircuitFailures returns recent failures recorded by the circuit breaker
func (h *AdminHandler) handleCircuitFailures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	failures := h.server.circuitBreaker.GetRecentFailures()
	patterns := h.server.circuitBreaker.DetectAttackPatterns()

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"failures":        failures,
		"attack_patterns": patterns,
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode circuit failures as JSON")
	}
}

// handleCircuitRecovery manages self-healing capabilities
func (h *AdminHandler) handleCircuitRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("action")
	if action == "" {
		http.Error(w, "Missing action parameter", http.StatusBadRequest)
		return
	}

	var message string
	switch action {
	case "enable":
		h.server.circuitBreaker.ActivateSelfHealing(true)
		message = "Self-healing enabled"
	case "disable":
		h.server.circuitBreaker.ActivateSelfHealing(false)
		message = "Self-healing disabled"
	case "heal":
		h.server.circuitBreaker.SelfHeal()
		message = "Manual healing triggered"
	default:
		http.Error(w, "Invalid action parameter (use 'enable', 'disable', or 'heal')", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":    "success",
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response as JSON")
	}
}

// handlePolicies manages security policies
func (h *AdminHandler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Return current policies
		policies := h.server.policyManager.GetAllPolicies()

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"policies":  policies,
			"timestamp": time.Now().Format(time.RFC3339),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error().Err(err).Msg("Failed to encode policies as JSON")
		}
		return
	}

	if r.Method == http.MethodPost {
		// Update a policy
		var policy Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "Invalid policy format: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := h.server.policyManager.UpdatePolicy(&policy); err != nil {
			http.Error(w, "Failed to update policy: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"status":    "success",
			"message":   "Policy updated",
			"timestamp": time.Now().Format(time.RFC3339),
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error().Err(err).Msg("Failed to encode response as JSON")
		}
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handlePolicyReload reloads policies from disk
func (h *AdminHandler) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := h.server.policyManager.LoadPolicies()
	if err != nil {
		http.Error(w, "Failed to reload policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":    "success",
		"message":   "Policies reloaded",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode response as JSON")
	}
}
