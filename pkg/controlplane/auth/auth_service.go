package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/controlplane/config"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrAttestationFailed     = errors.New("attestation verification failed")
	ErrInsufficientPrivilege = errors.New("insufficient privileges")
	ErrUserLocked            = errors.New("user account is locked")
	ErrMFARequired           = errors.New("multi-factor authentication required")
	ErrTokenExpired          = errors.New("token has expired")
	ErrInvalidToken          = errors.New("invalid token")
)

// AuthService implements the AuthService gRPC interface
type AuthService struct {
	blackicev1.UnimplementedAuthServiceServer

	config            *config.ControlPlaneConfig
	userStore         UserStore
	roleStore         RoleStore
	permissionStore   PermissionStore
	attestationClient AttestationClient
	tokenManager      TokenManager

	failedLoginAttempts map[string]int // username -> count
	failedLoginLock     sync.RWMutex
}

// UserStore defines the interface for user data storage
type UserStore interface {
	GetUser(ctx context.Context, id string) (*blackicev1.User, error)
	GetUserByUsername(ctx context.Context, username string) (*blackicev1.User, error)
	CreateUser(ctx context.Context, user *blackicev1.User) (string, error)
	UpdateUser(ctx context.Context, user *blackicev1.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, offset, limit int) ([]*blackicev1.User, error)
}

// RoleStore defines the interface for role data storage
type RoleStore interface {
	GetRole(ctx context.Context, id string) (*blackicev1.Role, error)
	CreateRole(ctx context.Context, role *blackicev1.Role) (string, error)
	UpdateRole(ctx context.Context, role *blackicev1.Role) error
	DeleteRole(ctx context.Context, id string) error
	ListRoles(ctx context.Context, offset, limit int) ([]*blackicev1.Role, error)
}

// PermissionStore defines the interface for permission operations
type PermissionStore interface {
	GetPermissionsForUser(ctx context.Context, userID string) ([]string, error)
	GetPermissionsForRole(ctx context.Context, roleID string) ([]string, error)
	AddPermissionToRole(ctx context.Context, roleID string, permission string) error
	RemovePermissionFromRole(ctx context.Context, roleID string, permission string) error
}

// AttestationClient interfaces with the attestation service
type AttestationClient interface {
	VerifyAttestation(ctx context.Context, attestation *blackicev1.Attestation) (bool, error)
	CreateChallenge(ctx context.Context, userID string, deviceID string, attestationType blackicev1.AttestationType) (*blackicev1.AttestationChallengeResponse, error)
}

// TokenManager handles JWT token operations
type TokenManager interface {
	GenerateToken(userID string, permissions []string, duration time.Duration) (string, error)
	ValidateToken(token string) (string, []string, error) // returns userID, permissions, error
	RevokeToken(token string) error
}

// NewAuthService creates a new authentication service
func NewAuthService(
	cfg *config.ControlPlaneConfig,
	userStore UserStore,
	roleStore RoleStore,
	permissionStore PermissionStore,
	attestationClient AttestationClient,
	tokenManager TokenManager,
) *AuthService {
	return &AuthService{
		config:              cfg,
		userStore:           userStore,
		roleStore:           roleStore,
		permissionStore:     permissionStore,
		attestationClient:   attestationClient,
		tokenManager:        tokenManager,
		failedLoginAttempts: make(map[string]int),
	}
}

// AuthenticateUser authenticates a user and returns a session token
func (s *AuthService) AuthenticateUser(ctx context.Context, req *blackicev1.AuthenticateUserRequest) (*blackicev1.AuthenticationResponse, error) {
	// Check if user account is locked due to too many failed attempts
	if s.isUserLocked(req.Username) {
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: "account temporarily locked due to too many failed login attempts",
			},
		}, status.Error(codes.PermissionDenied, "account locked")
	}

	// Retrieve user
	user, err := s.userStore.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.recordFailedLogin(req.Username)
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: "authentication failed",
			},
		}, status.Error(codes.Unauthenticated, "authentication failed")
	}

	// Check user status
	if user.Status != blackicev1.UserStatus_USER_STATUS_ACTIVE {
		s.recordFailedLogin(req.Username)
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: fmt.Sprintf("account is %s", user.Status.String()),
			},
		}, status.Error(codes.PermissionDenied, "account not active")
	}

	// Validate credentials based on auth factor type
	if err := s.validateCredentials(ctx, user, req); err != nil {
		s.recordFailedLogin(req.Username)
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: "invalid credentials",
			},
		}, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Get user permissions
	permissions, err := s.permissionStore.GetPermissionsForUser(ctx, user.Id)
	if err != nil {
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INTERNAL_ERROR,
				Message: "failed to retrieve permissions",
			},
		}, status.Error(codes.Internal, "failed to retrieve permissions")
	}

	// Generate tokens
	expiry := time.Duration(s.config.Auth.TokenExpiryMinutes) * time.Minute
	token, err := s.tokenManager.GenerateToken(user.Id, permissions, expiry)
	if err != nil {
		return &blackicev1.AuthenticationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INTERNAL_ERROR,
				Message: "failed to generate token",
			},
		}, status.Error(codes.Internal, "failed to generate token")
	}

	// Successful login - reset failed attempts
	s.resetFailedLoginAttempts(req.Username)

	return &blackicev1.AuthenticationResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "authentication successful",
		},
		SessionToken: token,
		ExpiryUnixNs: time.Now().Add(expiry).UnixNano(),
		User:         user,
		Permissions:  permissions,
	}, nil
}

// ValidateToken validates a session token and returns claims
func (s *AuthService) ValidateToken(ctx context.Context, req *blackicev1.ValidateTokenRequest) (*blackicev1.TokenValidationResponse, error) {
	userID, permissions, err := s.tokenManager.ValidateToken(req.Token)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return &blackicev1.TokenValidationResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_UNAUTHORIZED,
					Message: "token expired",
				},
			}, status.Error(codes.Unauthenticated, "token expired")
		}
		return &blackicev1.TokenValidationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: "invalid token",
			},
		}, status.Error(codes.Unauthenticated, "invalid token")
	}

	// Retrieve user to get role IDs
	user, err := s.userStore.GetUser(ctx, userID)
	if err != nil {
		return &blackicev1.TokenValidationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_NOT_FOUND,
				Message: "user not found",
			},
		}, status.Error(codes.NotFound, "user not found")
	}

	// Calculate when the token will expire
	// Note: In a real implementation, this would be extracted from the token itself
	tokenLifetime := time.Duration(s.config.Auth.TokenExpiryMinutes) * time.Minute
	expiryTime := time.Now().Add(tokenLifetime).UnixNano()

	return &blackicev1.TokenValidationResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "token validated successfully",
		},
		UserId:       userID,
		RoleIds:      user.RoleIds,
		Permissions:  permissions,
		ExpiryUnixNs: expiryTime,
	}, nil
}

// AuthorizeOperation checks if a user has permission for a specific operation
func (s *AuthService) AuthorizeOperation(ctx context.Context, req *blackicev1.AuthorizeOperationRequest) (*blackicev1.AuthorizationResponse, error) {
	// Verify attestation if provided
	if req.UserAttestation != nil {
		verified, err := s.attestationClient.VerifyAttestation(ctx, req.UserAttestation)
		if err != nil || !verified {
			return &blackicev1.AuthorizationResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_UNAUTHORIZED,
					Message: "attestation verification failed",
				},
				Authorized: false,
				Reason:     "attestation verification failed",
			}, status.Error(codes.PermissionDenied, "attestation verification failed")
		}
	}

	// Get user permissions
	permissions, err := s.permissionStore.GetPermissionsForUser(ctx, req.UserId)
	if err != nil {
		return &blackicev1.AuthorizationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INTERNAL_ERROR,
				Message: "failed to retrieve permissions",
			},
			Authorized: false,
			Reason:     "failed to retrieve permissions",
		}, status.Error(codes.Internal, "failed to retrieve permissions")
	}

	// Check if user has the required permission
	requiredPermission := fmt.Sprintf("%s:%s", req.Resource, req.Action)
	if req.ResourceId != "" {
		requiredPermission = fmt.Sprintf("%s:%s:%s", req.Resource, req.Action, req.ResourceId)
	}

	// Also check for wildcard permissions
	wildcardPermission := fmt.Sprintf("%s:%s:*", req.Resource, req.Action)
	globalWildcardPermission := fmt.Sprintf("%s:*", req.Resource)
	superUserPermission := "*:*"

	authorized := false
	for _, perm := range permissions {
		if perm == requiredPermission || perm == wildcardPermission ||
			perm == globalWildcardPermission || perm == superUserPermission {
			authorized = true
			break
		}
	}

	if !authorized {
		return &blackicev1.AuthorizationResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_UNAUTHORIZED,
				Message: "operation not authorized",
			},
			Authorized:         false,
			Reason:             "insufficient permissions",
			MissingPermissions: []string{requiredPermission},
		}, status.Error(codes.PermissionDenied, "operation not authorized")
	}

	return &blackicev1.AuthorizationResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "operation authorized",
		},
		Authorized: true,
	}, nil
}

// ManageRoles creates, updates, or deletes roles
func (s *AuthService) ManageRoles(ctx context.Context, req *blackicev1.ManageRolesRequest) (*blackicev1.ManageRolesResponse, error) {
	// Verify admin attestation
	if req.AdminAttestation != nil {
		verified, err := s.attestationClient.VerifyAttestation(ctx, req.AdminAttestation)
		if err != nil || !verified {
			return &blackicev1.ManageRolesResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_UNAUTHORIZED,
					Message: "attestation verification failed",
				},
			}, status.Error(codes.PermissionDenied, "attestation verification failed")
		}
	}

	var roleID string
	var err error

	// Process based on operation type
	switch op := req.Operation.(type) {
	case *blackicev1.ManageRolesRequest_CreateRole:
		roleID, err = s.roleStore.CreateRole(ctx, op.CreateRole)
		if err != nil {
			return &blackicev1.ManageRolesResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_INTERNAL_ERROR,
					Message: "failed to create role",
				},
			}, status.Error(codes.Internal, "failed to create role")
		}

	case *blackicev1.ManageRolesRequest_UpdateRole:
		err = s.roleStore.UpdateRole(ctx, op.UpdateRole)
		roleID = op.UpdateRole.Id
		if err != nil {
			return &blackicev1.ManageRolesResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_INTERNAL_ERROR,
					Message: "failed to update role",
				},
			}, status.Error(codes.Internal, "failed to update role")
		}

	case *blackicev1.ManageRolesRequest_DeleteRoleId:
		err = s.roleStore.DeleteRole(ctx, op.DeleteRoleId)
		roleID = op.DeleteRoleId
		if err != nil {
			return &blackicev1.ManageRolesResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_INTERNAL_ERROR,
					Message: "failed to delete role",
				},
			}, status.Error(codes.Internal, "failed to delete role")
		}

	default:
		return &blackicev1.ManageRolesResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INVALID_INPUT,
				Message: "invalid operation",
			},
		}, status.Error(codes.InvalidArgument, "invalid operation")
	}

	// Record the operation in a ledger (audit trail)
	// This would be implemented in a real system
	ledgerEntry := &blackicev1.LedgerEntry{
		EntryId:           generateUniqueID(),
		CommittedAtUnixNs: time.Now().UnixNano(),
	}

	return &blackicev1.ManageRolesResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "role operation completed successfully",
		},
		RoleId:                  roleID,
		LedgerEntryConfirmation: ledgerEntry,
	}, nil
}

// ManagePermissions assigns or revokes permissions for roles
func (s *AuthService) ManagePermissions(ctx context.Context, req *blackicev1.ManagePermissionsRequest) (*blackicev1.ManagePermissionsResponse, error) {
	// Verify admin attestation
	if req.AdminAttestation != nil {
		verified, err := s.attestationClient.VerifyAttestation(ctx, req.AdminAttestation)
		if err != nil || !verified {
			return &blackicev1.ManagePermissionsResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_UNAUTHORIZED,
					Message: "attestation verification failed",
				},
			}, status.Error(codes.PermissionDenied, "attestation verification failed")
		}
	}

	// Check if role exists
	_, err := s.roleStore.GetRole(ctx, req.RoleId)
	if err != nil {
		return &blackicev1.ManagePermissionsResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_NOT_FOUND,
				Message: "role not found",
			},
		}, status.Error(codes.NotFound, "role not found")
	}

	// Process the operation
	switch op := req.Operation.(type) {
	case *blackicev1.ManagePermissionsRequest_AddPermissions:
		for _, perm := range op.AddPermissions.Permissions {
			permStr := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if perm.Condition != "" {
				permStr = fmt.Sprintf("%s:%s", permStr, perm.Condition)
			}

			err = s.permissionStore.AddPermissionToRole(ctx, req.RoleId, permStr)
			if err != nil {
				return &blackicev1.ManagePermissionsResponse{
					Status: &blackicev1.Status{
						Code:    blackicev1.Status_INTERNAL_ERROR,
						Message: "failed to add permissions",
					},
				}, status.Error(codes.Internal, "failed to add permissions")
			}
		}

	case *blackicev1.ManagePermissionsRequest_RemovePermissions:
		for _, perm := range op.RemovePermissions.Permissions {
			permStr := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
			if perm.Condition != "" {
				permStr = fmt.Sprintf("%s:%s", permStr, perm.Condition)
			}

			err = s.permissionStore.RemovePermissionFromRole(ctx, req.RoleId, permStr)
			if err != nil {
				return &blackicev1.ManagePermissionsResponse{
					Status: &blackicev1.Status{
						Code:    blackicev1.Status_INTERNAL_ERROR,
						Message: "failed to remove permissions",
					},
				}, status.Error(codes.Internal, "failed to remove permissions")
			}
		}

	default:
		return &blackicev1.ManagePermissionsResponse{
			Status: &blackicev1.Status{
				Code:    blackicev1.Status_INVALID_INPUT,
				Message: "invalid operation",
			},
		}, status.Error(codes.InvalidArgument, "invalid operation")
	}

	// Record the operation in a ledger (audit trail)
	ledgerEntry := &blackicev1.LedgerEntry{
		EntryId:           generateUniqueID(),
		CommittedAtUnixNs: time.Now().UnixNano(),
	}

	return &blackicev1.ManagePermissionsResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "permissions updated successfully",
		},
		LedgerEntryConfirmation: ledgerEntry,
	}, nil
}

// CreateAttestationChallenge creates a challenge for hardware attestation
func (s *AuthService) CreateAttestationChallenge(ctx context.Context, req *blackicev1.CreateAttestationChallengeRequest) (*blackicev1.AttestationChallengeResponse, error) {
	// Delegate to attestation client
	return s.attestationClient.CreateChallenge(ctx, req.UserId, req.DeviceId, req.AttestationType)
}

// VerifyAttestation verifies the response to an attestation challenge
func (s *AuthService) VerifyAttestation(ctx context.Context, req *blackicev1.VerifyAttestationRequest) (*blackicev1.VerifyAttestationResponse, error) {
	// For verification, we would typically:
	// 1. Retrieve the challenge from storage
	// 2. Verify the attestation data against the challenge
	// 3. Record the verification result

	// Since we don't have the full implementation, we'll return a mock response
	return &blackicev1.VerifyAttestationResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_ERROR,
			Message: "attestation verification not fully implemented",
		},
		Verified:       false,
		VerificationId: generateUniqueID(),
	}, status.Error(codes.Unimplemented, "attestation verification not fully implemented")
}

// Helper methods

// validateCredentials validates user credentials based on the provided auth factor
func (s *AuthService) validateCredentials(ctx context.Context, user *blackicev1.User, req *blackicev1.AuthenticateUserRequest) error {
	// This would be replaced with actual validation logic
	// based on the type of credentials provided

	switch req.AuthFactor.(type) {
	case *blackicev1.AuthenticateUserRequest_PasswordCredential:
		// In a real implementation, we would:
		// 1. Hash the provided password
		// 2. Compare with stored hash
		// 3. Check password expiry
		return nil // Simulating success

	case *blackicev1.AuthenticateUserRequest_HardwareKeyCredential:
		// Verify hardware attestation
		// This would involve complex verification of the hardware signature
		return nil // Simulating success

	case *blackicev1.AuthenticateUserRequest_TotpCredential:
		// Verify TOTP code
		// This would involve time-based code verification
		return nil // Simulating success

	case *blackicev1.AuthenticateUserRequest_CertificateCredential:
		// Verify certificate and signature
		// This would involve PKI verification
		return nil // Simulating success

	default:
		return ErrInvalidCredentials
	}
}

// isUserLocked checks if a user account is locked due to too many failed attempts
func (s *AuthService) isUserLocked(username string) bool {
	s.failedLoginLock.RLock()
	defer s.failedLoginLock.RUnlock()

	attempts, exists := s.failedLoginAttempts[username]
	if !exists {
		return false
	}

	return attempts >= s.config.Auth.FailedLoginLockoutThreshold
}

// recordFailedLogin increments the failed login counter for a user
func (s *AuthService) recordFailedLogin(username string) {
	s.failedLoginLock.Lock()
	defer s.failedLoginLock.Unlock()

	s.failedLoginAttempts[username]++
}

// resetFailedLoginAttempts resets the failed login counter for a user
func (s *AuthService) resetFailedLoginAttempts(username string) {
	s.failedLoginLock.Lock()
	defer s.failedLoginLock.Unlock()

	delete(s.failedLoginAttempts, username)
}

// generateUniqueID generates a unique ID for ledger entries, etc.
func generateUniqueID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	return hex.EncodeToString(b)
}
