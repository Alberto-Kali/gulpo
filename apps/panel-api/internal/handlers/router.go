package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fear/gulpo/apps/panel-api/internal/auth"
	"github.com/fear/gulpo/apps/panel-api/internal/config"
	"github.com/fear/gulpo/apps/panel-api/internal/domain"
	"github.com/fear/gulpo/apps/panel-api/internal/store"
)

type API struct {
	cfg   config.Config
	store *store.PostgresStore
}

func New(cfg config.Config, st *store.PostgresStore) http.Handler {
	api := &API{cfg: cfg, store: st}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", api.handleHealth)
	mux.HandleFunc("/api/healthz", api.handleHealth)
	mux.HandleFunc("/api/admin/login", api.handleAdminLogin)
	mux.HandleFunc("/api/subscriptions/", api.handleSubscription)
	mux.HandleFunc("/api/subj/", api.handleSubj)
	mux.HandleFunc("/api/camouflage/", api.handleCamouflage)
	mux.HandleFunc("/api/camouflage", api.handleCamouflage)
	mux.HandleFunc("/api/node/enroll", api.handleNodeEnroll)
	mux.HandleFunc("/api/node/heartbeat", api.handleNodeHeartbeat)
	mux.HandleFunc("/api/node/sync", api.handleNodeSync)
	mux.HandleFunc("/api/node/usage/batch", api.handleNodeUsageBatch)
	mux.HandleFunc("/api/node/sessions/snapshot", api.handleNodeSessionsSnapshot)
	mux.HandleFunc("/api/node/events/batch", api.handleNodeEventsBatch)

	mux.Handle("/api/admin/users", api.adminAuth(http.HandlerFunc(api.handleUsers)))
	mux.Handle("/api/admin/users/", api.adminAuth(http.HandlerFunc(api.handleUserByID)))
	mux.Handle("/api/admin/nodes", api.adminAuth(http.HandlerFunc(api.handleNodes)))
	mux.Handle("/api/admin/nodes/", api.adminAuth(http.HandlerFunc(api.handleNodeByID)))
	mux.Handle("/api/admin/dashboard/summary", api.adminAuth(http.HandlerFunc(api.handleDashboardSummary)))
	mux.Handle("/api/admin/presence/summary", api.adminAuth(http.HandlerFunc(api.handlePresenceSummary)))
	mux.Handle("/api/admin/config/global", api.adminAuth(http.HandlerFunc(api.handleGlobalConfig)))

	return withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/api/") {
			clone := r.Clone(r.Context())
			clone.URL.Path = "/api/" + strings.TrimPrefix(r.URL.Path, "/api/api/")
			r = clone
		}
		mux.ServeHTTP(w, r)
	}))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/camouflage") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Node-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		if _, err := auth.VerifyJWT(token, a.cfg.JWTSecret); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) nodeAuth(r *http.Request) (domain.Node, error) {
	apiKey := r.Header.Get("X-Node-Key")
	if apiKey == "" {
		return domain.Node{}, errors.New("missing node key")
	}
	return a.store.GetNodeByAPIKey(r.Context(), apiKey)
}

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	summary, err := a.store.GetDashboardSummary(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *API) handlePresenceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = a.store.ReconcileStaleNodes(r.Context(), a.cfg.NodeOfflineTimeout)
	summary, err := a.store.GetPresenceSummary(r.Context(), 60*time.Second)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *API) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Login    string `json:"login"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	login := strings.TrimSpace(req.Login)
	if login == "" {
		login = strings.TrimSpace(req.Email)
	}
	admin, err := a.store.GetAdminByLogin(r.Context(), login)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if !auth.VerifyPassword(admin.PasswordHash, req.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, err := auth.IssueJWT(admin.ID, a.cfg.JWTSecret, 24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (a *API) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := a.store.ListUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var req struct {
			ExternalID        *string               `json:"external_id"`
			Name              string                `json:"name"`
			Status            domain.UserStatus     `json:"status"`
			TrafficLimitBytes int64                 `json:"traffic_limit_bytes"`
			NodeAccessMode    domain.NodeAccessMode `json:"node_access_mode"`
			DeviceLimit       int                   `json:"subscription_device_limit"`
			Tags              []string              `json:"tags"`
			AllowedNodeIDs    []string              `json:"allowed_node_ids"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		user, err := a.store.CreateUser(r.Context(), domain.User{
			ExternalID:              req.ExternalID,
			Name:                    req.Name,
			Status:                  req.Status,
			TrafficLimitBytes:       req.TrafficLimitBytes,
			NodeAccessMode:          req.NodeAccessMode,
			SubscriptionDeviceLimit: req.DeviceLimit,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if len(req.Tags) > 0 {
			user.Tags, _ = a.store.AttachTagsToUser(r.Context(), user.ID, req.Tags)
		}
		if len(req.AllowedNodeIDs) > 0 {
			_ = a.store.ReplaceAllowedNodes(r.Context(), user.ID, req.AllowedNodeIDs)
			user.AllowedNodeIDs = req.AllowedNodeIDs
		}
		writeJSON(w, http.StatusCreated, user)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleUserByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "tags" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Tags []string `json:"tags"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		tags, err := a.store.AttachTagsToUser(r.Context(), id, req.Tags)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, tags)
		return
	}
	if len(parts) == 2 && parts[1] == "protocol-access" {
		switch r.Method {
		case http.MethodGet:
			entries, err := a.store.ListUserProtocolAccess(r.Context(), id)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, entries)
		case http.MethodPut:
			var req struct {
				Entries []domain.UserNodeProtocolAccess `json:"entries"`
			}
			if err := readJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			for i := range req.Entries {
				req.Entries[i].UserID = id
			}
			if err := a.store.ReplaceUserProtocolAccess(r.Context(), id, req.Entries); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "subscription" && parts[2] == "devices" && r.Method == http.MethodGet {
		devices, err := a.store.ListUserSubscriptionDevices(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, devices)
		return
	}
	if len(parts) == 3 && parts[1] == "subscription" && parts[2] == "requests" && r.Method == http.MethodGet {
		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var parsed int
			if _, err := fmt.Sscanf(raw, "%d", &parsed); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		events, err := a.store.ListUserSubscriptionRequestEvents(r.Context(), id, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
		return
	}
	if len(parts) == 2 && parts[1] == "subscription" && r.Method == http.MethodPost {
		token, err := a.store.RotateSubscriptionToken(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"subscription_token": token})
		return
	}
	if len(parts) == 3 && parts[1] == "subscription" && parts[2] == "rotate" && r.Method == http.MethodPost {
		token, err := a.store.RotateSubscriptionToken(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"subscription_token": token})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			ExternalID        *string                `json:"external_id"`
			Name              *string                `json:"name"`
			Status            *domain.UserStatus     `json:"status"`
			TrafficLimitBytes *int64                 `json:"traffic_limit_bytes"`
			NodeAccessMode    *domain.NodeAccessMode `json:"node_access_mode"`
			DeviceLimit       *int                   `json:"subscription_device_limit"`
			AllowedNodeIDs    *[]string              `json:"allowed_node_ids"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		users, err := a.store.ListUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var current *domain.User
		for i := range users {
			if users[i].ID == id {
				current = &users[i]
				break
			}
		}
		if current == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		updated := domain.User{
			ExternalID:              current.ExternalID,
			Name:                    current.Name,
			Status:                  current.Status,
			TrafficLimitBytes:       current.TrafficLimitBytes,
			NodeAccessMode:          current.NodeAccessMode,
			SubscriptionDeviceLimit: current.SubscriptionDeviceLimit,
		}
		if req.ExternalID != nil {
			updated.ExternalID = req.ExternalID
		}
		if req.Name != nil {
			updated.Name = *req.Name
		}
		if req.Status != nil {
			updated.Status = *req.Status
		}
		if req.TrafficLimitBytes != nil {
			updated.TrafficLimitBytes = *req.TrafficLimitBytes
		}
		if req.NodeAccessMode != nil {
			updated.NodeAccessMode = *req.NodeAccessMode
		}
		if req.DeviceLimit != nil {
			updated.SubscriptionDeviceLimit = *req.DeviceLimit
		}
		user, err := a.store.UpdateUser(r.Context(), id, updated)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if req.AllowedNodeIDs != nil {
			_ = a.store.ReplaceAllowedNodes(r.Context(), id, *req.AllowedNodeIDs)
			user.AllowedNodeIDs = *req.AllowedNodeIDs
		}
		writeJSON(w, http.StatusOK, user)
	case http.MethodDelete:
		if err := a.store.DeleteUser(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = a.store.ReconcileStaleNodes(r.Context(), a.cfg.NodeOfflineTimeout)
		nodes, err := a.store.ListNodes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, nodes)
	case http.MethodPost:
		var req struct {
			Name                string                     `json:"name"`
			Domain              string                     `json:"domain"`
			Port                int                        `json:"port"`
			Status              domain.NodeStatus          `json:"status"`
			DefaultAccessPolicy domain.DefaultAccessPolicy `json:"default_access_policy"`
			DefaultAccessTag    *string                    `json:"default_access_tag"`
			AgentVersion        string                     `json:"agent_version"`
			SingboxVersion      string                     `json:"singbox_version"`
			CertificateMode     domain.CertificateMode     `json:"certificate_mode"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := validateCertificateChoice(req.Domain, req.CertificateMode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		node, err := a.store.CreateNode(r.Context(), domain.Node{
			Name:                req.Name,
			Domain:              req.Domain,
			Port:                req.Port,
			Status:              req.Status,
			DefaultAccessPolicy: req.DefaultAccessPolicy,
			DefaultAccessTag:    req.DefaultAccessTag,
			AgentVersion:        req.AgentVersion,
			SingboxVersion:      req.SingboxVersion,
			CertificateMode:     req.CertificateMode,
			ConfigOverride:      []byte(`{}`),
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, node)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleNodeByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/nodes/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "enroll-token" && r.Method == http.MethodPost {
		token, err := a.store.RotateEnrollToken(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"enroll_token": token})
		return
	}
	if len(parts) == 3 && parts[1] == "enroll-token" && parts[2] == "rotate" && r.Method == http.MethodPost {
		token, err := a.store.RotateEnrollToken(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"enroll_token": token})
		return
	}
	if len(parts) == 2 && parts[1] == "commands" && r.Method == http.MethodPost {
		var req struct {
			Type    domain.CommandType `json:"type"`
			Payload map[string]any     `json:"payload"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		payload, _ := json.Marshal(req.Payload)
		cmd, err := a.store.CreateNodeCommand(r.Context(), domain.NodeCommand{
			NodeID:  id,
			Type:    req.Type,
			Payload: payload,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, cmd)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		_ = a.store.ReconcileStaleNodes(r.Context(), a.cfg.NodeOfflineTimeout)
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var parsed int
			if _, err := fmt.Sscanf(raw, "%d", &parsed); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		events, err := a.store.ListNodeEvents(r.Context(), id, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, events)
		return
	}
	if len(parts) == 2 && parts[1] == "config" {
		switch r.Method {
		case http.MethodGet:
			cfg, err := a.store.GetNodeConfig(r.Context(), id)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, json.RawMessage(cfg))
		case http.MethodPatch:
			var body json.RawMessage
			if err := readJSON(r, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := validateNodeConfigPayload(body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := a.store.UpdateNodeConfig(r.Context(), id, body); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Name                *string                     `json:"name"`
			Domain              *string                     `json:"domain"`
			Port                *int                        `json:"port"`
			Status              *domain.NodeStatus          `json:"status"`
			DefaultAccessPolicy *domain.DefaultAccessPolicy `json:"default_access_policy"`
			DefaultAccessTag    *string                     `json:"default_access_tag"`
			AgentVersion        *string                     `json:"agent_version"`
			SingboxVersion      *string                     `json:"singbox_version"`
			CertificateMode     *domain.CertificateMode     `json:"certificate_mode"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		nodes, err := a.store.ListNodes(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		var current *domain.Node
		for i := range nodes {
			if nodes[i].ID == id {
				current = &nodes[i]
				break
			}
		}
		if current == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}
		updated := domain.Node{
			Name:                current.Name,
			Domain:              current.Domain,
			Port:                current.Port,
			Status:              current.Status,
			DefaultAccessPolicy: current.DefaultAccessPolicy,
			DefaultAccessTag:    current.DefaultAccessTag,
			AgentVersion:        current.AgentVersion,
			SingboxVersion:      current.SingboxVersion,
			CertificateMode:     current.CertificateMode,
		}
		if req.Name != nil {
			updated.Name = *req.Name
		}
		if req.Domain != nil {
			updated.Domain = *req.Domain
		}
		if req.Port != nil {
			updated.Port = *req.Port
		}
		if req.Status != nil {
			updated.Status = *req.Status
		}
		if req.DefaultAccessPolicy != nil {
			updated.DefaultAccessPolicy = *req.DefaultAccessPolicy
		}
		if req.DefaultAccessTag != nil {
			updated.DefaultAccessTag = req.DefaultAccessTag
		}
		if req.AgentVersion != nil {
			updated.AgentVersion = *req.AgentVersion
		}
		if req.SingboxVersion != nil {
			updated.SingboxVersion = *req.SingboxVersion
		}
		if req.CertificateMode != nil {
			updated.CertificateMode = *req.CertificateMode
		}
		if err := validateCertificateChoice(updated.Domain, updated.CertificateMode); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		node, err := a.store.UpdateNode(r.Context(), id, updated)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, node)
	case http.MethodDelete:
		if err := a.store.DeleteNode(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleGlobalConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := a.store.GetGlobalConfig(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, json.RawMessage(cfg.ConfigJSON))
	case http.MethodPatch:
		var body json.RawMessage
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cfg, err := a.store.UpdateGlobalConfig(r.Context(), body)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, json.RawMessage(cfg.ConfigJSON))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type camouflageSite struct {
	Name    string `json:"name,omitempty"`
	Origin  string `json:"origin,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type camouflageConfig struct {
	Enabled bool              `json:"enabled,omitempty"`
	Sites   []camouflageSite  `json:"sites,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (a *API) handleCamouflage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, err := a.store.GetGlobalConfig(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	site, extraHeaders, ok := activeCamouflageSite(cfg.ConfigJSON)
	if !ok {
		http.NotFound(w, r)
		return
	}
	targetURL, err := camouflageTargetURL(site.Origin, r)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", coalesceHeader(r.Header.Get("User-Agent"), "Mozilla/5.0"))
	req.Header.Set("Accept", coalesceHeader(r.Header.Get("Accept"), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
	req.Header.Set("Accept-Language", coalesceHeader(r.Header.Get("Accept-Language"), "en-US,en;q=0.9"))
	req.Header.Set("Accept-Encoding", "identity")
	for key, value := range extraHeaders {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if resp.StatusCode == http.StatusNotFound && camouflageRequestPath(r) != "/" {
		resp.Body.Close()
		targetURL, err = camouflageTargetURLForPath(site.Origin, "/", "")
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		req, err = http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		req.Header.Set("User-Agent", coalesceHeader(r.Header.Get("User-Agent"), "Mozilla/5.0"))
		req.Header.Set("Accept", coalesceHeader(r.Header.Get("Accept"), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
		req.Header.Set("Accept-Language", coalesceHeader(r.Header.Get("Accept-Language"), "en-US,en;q=0.9"))
		req.Header.Set("Accept-Encoding", "identity")
		for key, value := range extraHeaders {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				req.Header.Set(key, value)
			}
		}
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	}
	defer resp.Body.Close()
	copyCamouflageHeaders(w.Header(), resp.Header)
	if location := resp.Header.Get("Location"); location != "" {
		if rewritten := rewriteCamouflageLocation(site.Origin, location); rewritten != "" {
			w.Header().Set("Location", rewritten)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, resp.Body)
	}
}

func activeCamouflageSite(raw json.RawMessage) (camouflageSite, map[string]string, bool) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return camouflageSite{}, nil, false
	}
	rawCamouflage, ok := root["camouflage"]
	if !ok {
		return camouflageSite{}, nil, false
	}
	body, err := json.Marshal(rawCamouflage)
	if err != nil {
		return camouflageSite{}, nil, false
	}
	var cfg camouflageConfig
	if err := json.Unmarshal(body, &cfg); err != nil || !cfg.Enabled {
		return camouflageSite{}, nil, false
	}
	for _, site := range cfg.Sites {
		if strings.TrimSpace(site.Origin) == "" {
			continue
		}
		if site.Enabled != nil && !*site.Enabled {
			continue
		}
		return site, cfg.Headers, true
	}
	return camouflageSite{}, nil, false
}

func camouflageTargetURL(origin string, r *http.Request) (string, error) {
	return camouflageTargetURLForPath(origin, camouflageRequestPath(r), r.URL.RawQuery)
}

func camouflageTargetURLForPath(origin string, requestPath string, rawQuery string) (string, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(origin), "/"))
	if err != nil {
		return "", err
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return "", fmt.Errorf("camouflage origin must use http or https")
	}
	target := *base
	target.Path = singleJoiningSlash(base.EscapedPath(), requestPath)
	target.RawQuery = rawQuery
	target.Fragment = ""
	return target.String(), nil
}

func camouflageRequestPath(r *http.Request) string {
	if forwardedPath := strings.TrimSpace(r.Header.Get("X-Gulpo-Camouflage-Path")); forwardedPath != "" {
		if !strings.HasPrefix(forwardedPath, "/") {
			return "/" + forwardedPath
		}
		return forwardedPath
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/api/camouflage")
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func copyCamouflageHeaders(dst, src http.Header) {
	for key, values := range src {
		if skipCamouflageHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func skipCamouflageHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-encoding", "content-length":
		return true
	default:
		return false
	}
}

func rewriteCamouflageLocation(origin string, location string) string {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(origin), "/"))
	if err != nil {
		return location
	}
	resolved, err := base.Parse(location)
	if err != nil {
		return location
	}
	if resolved.Host == base.Host && resolved.Scheme == base.Scheme {
		resolved.Scheme = ""
		resolved.Host = ""
	}
	return resolved.String()
}

func singleJoiningSlash(left, right string) string {
	if left == "" {
		left = "/"
	}
	if right == "" {
		right = "/"
	}
	leftSlash := strings.HasSuffix(left, "/")
	rightSlash := strings.HasPrefix(right, "/")
	switch {
	case leftSlash && rightSlash:
		return left + strings.TrimPrefix(right, "/")
	case !leftSlash && !rightSlash:
		return left + "/" + right
	default:
		return left + right
	}
}

func coalesceHeader(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (a *API) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	user, err := a.store.GetUserBySubscriptionToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	event, ok := a.recordSubscriptionRequest(r, user, "subscriptions")
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not record subscription request"})
		return
	}
	decision, err := a.checkSubscriptionDevice(r, user, event)
	if decision == subscriptionDeviceMissingHWID {
		writeJSON(w, http.StatusOK, emptySubscriptionEnvelope(user, "subscription hwid is required for this user"))
		return
	}
	if !writeBlockedSubscription(w, decision, err) {
		return
	}
	envelope, err := a.store.BuildSubscription(r.Context(), user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

func (a *API) handleSubj(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/subj/")
	user, err := a.store.GetUserBySubscriptionToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	event, ok := a.recordSubscriptionRequest(r, user, "subj")
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not record subscription request"})
		return
	}
	decision, err := a.checkSubscriptionDevice(r, user, event)
	if decision == subscriptionDeviceMissingHWID {
		writeJSON(w, http.StatusOK, emptyProfilePage(user, "subscription hwid is required for this user"))
		return
	}
	if !writeBlockedSubscription(w, decision, err) {
		return
	}
	profiles, err := a.store.BuildProfilePage(r.Context(), user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (a *API) recordSubscriptionRequest(r *http.Request, user domain.User, endpoint string) (domain.SubscriptionRequestEvent, bool) {
	event := subscriptionRequestEventFromHTTP(r, user.ID, endpoint)
	if err := a.store.RecordSubscriptionRequest(r.Context(), event); err != nil {
		log.Printf("record subscription request failed: %v", err)
		return event, false
	}
	return event, true
}

type subscriptionDeviceDecision string

const (
	subscriptionDeviceAllowed     subscriptionDeviceDecision = "allowed"
	subscriptionDeviceMissingHWID subscriptionDeviceDecision = "missing_hwid"
	subscriptionDeviceLimit       subscriptionDeviceDecision = "limit"
	subscriptionDeviceFailed      subscriptionDeviceDecision = "failed"
)

func (a *API) checkSubscriptionDevice(r *http.Request, user domain.User, event domain.SubscriptionRequestEvent) (subscriptionDeviceDecision, error) {
	if err := a.store.RegisterSubscriptionDevice(r.Context(), user, event); err != nil {
		switch {
		case errors.Is(err, store.ErrSubscriptionDeviceIDRequired):
			return subscriptionDeviceMissingHWID, err
		case errors.Is(err, store.ErrSubscriptionDeviceLimitReached):
			return subscriptionDeviceLimit, err
		default:
			return subscriptionDeviceFailed, err
		}
	}
	return subscriptionDeviceAllowed, nil
}

func writeBlockedSubscription(w http.ResponseWriter, decision subscriptionDeviceDecision, err error) bool {
	switch decision {
	case subscriptionDeviceAllowed:
		return true
	case subscriptionDeviceLimit:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "subscription device limit reached"})
	case subscriptionDeviceFailed:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "subscription device check failed"})
	}
	return false
}

func emptySubscriptionEnvelope(user domain.User, message string) domain.SubscriptionEnvelope {
	return domain.SubscriptionEnvelope{
		Version: "1",
		Nodes:   []domain.SubscriptionNode{},
		Meta: map[string]interface{}{
			"user_id":      user.ID,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"transport":    "multi",
			"subscription": user.SubscriptionToken,
			"message":      message,
		},
	}
}

func emptyProfilePage(user domain.User, message string) domain.ProfilePageResponse {
	return domain.ProfilePageResponse{
		UserName:     user.Name,
		UserStatus:   user.Status,
		Subscription: user.SubscriptionToken,
		Profiles:     []domain.ProfileItem{},
		Message:      message,
	}
}

func subscriptionRequestEventFromHTTP(r *http.Request, userID, endpoint string) domain.SubscriptionRequestEvent {
	clientIP := clientIPFromRequest(r)
	userAgent := strings.TrimSpace(r.UserAgent())
	deviceID, deviceSource := deviceIdentifierFromRequest(r)
	queryJSON := mustJSON(subscriptionQueryParams(r))
	headersJSON := mustJSON(subscriptionHeaders(r))
	fingerprint := requestFingerprint(clientIP, userAgent, r.URL.RawQuery, headersJSON)
	deviceKey := fingerprint
	if deviceID != "" {
		deviceKey = stableHash(deviceSource + "\x00" + deviceID)
	} else {
		deviceSource = "fingerprint"
	}
	return domain.SubscriptionRequestEvent{
		UserID:             userID,
		Endpoint:           endpoint,
		ClientIP:           clientIP,
		UserAgent:          userAgent,
		DeviceKey:          deviceKey,
		DeviceIdentifier:   deviceID,
		DeviceSource:       deviceSource,
		RequestFingerprint: fingerprint,
		QueryParams:        queryJSON,
		Headers:            headersJSON,
		CreatedAt:          time.Now().UTC(),
	}
}

func (a *API) handleNodeEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EnrollToken    string `json:"enroll_token"`
		AgentVersion   string `json:"agent_version"`
		SingboxVersion string `json:"singbox_version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	node, err := a.store.EnrollNode(r.Context(), req.EnrollToken, req.AgentVersion, req.SingboxVersion)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enroll token"})
		return
	}
	desired, err := a.store.BuildNodeDesiredConfig(r.Context(), node)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	commands, _ := a.store.ListPendingNodeCommands(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, domain.EnrollResponse{
		NodeID:        node.ID,
		NodeAPIKey:    node.APIKey,
		DesiredConfig: desired,
		Commands:      commands,
	})
}

func (a *API) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := a.nodeAuth(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		AgentVersion   string `json:"agent_version"`
		SingboxVersion string `json:"singbox_version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.TouchNodeHeartbeat(r.Context(), node.ID, req.AgentVersion, req.SingboxVersion); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleNodeSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := a.nodeAuth(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		AgentVersion   string `json:"agent_version"`
		SingboxVersion string `json:"singbox_version"`
		CommandResults []struct {
			ID     string               `json:"id"`
			Status domain.CommandStatus `json:"status"`
			Result string               `json:"result"`
		} `json:"command_results"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.TouchNodeHeartbeat(r.Context(), node.ID, req.AgentVersion, req.SingboxVersion)
	for _, result := range req.CommandResults {
		_ = a.store.CompleteNodeCommand(r.Context(), result.ID, result.Status, result.Result)
	}
	desired, err := a.store.BuildNodeDesiredConfig(r.Context(), node)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	commands, _ := a.store.ListPendingNodeCommands(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":        node.ID,
		"desired_config": desired,
		"commands":       commands,
	})
}

func (a *API) handleNodeUsageBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := a.nodeAuth(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		Records []domain.UsageRecord `json:"records"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.SaveUsageBatch(r.Context(), node.ID, req.Records); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleNodeSessionsSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := a.nodeAuth(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		Sessions []domain.UserNodeSessionPresence `json:"sessions"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.UpsertSessionSnapshot(r.Context(), node.ID, req.Sessions); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleNodeEventsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	node, err := a.nodeAuth(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		Events []domain.NodeEvent `json:"events"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.CreateNodeEvents(r.Context(), node.ID, req.Events); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validateCertificateChoice(domainValue string, mode domain.CertificateMode) error {
	host := domainValue
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	host = strings.TrimSpace(host)
	if mode != domain.CertificateModeACME {
		return nil
	}
	if host == "" {
		return errors.New("domain is required for ACME")
	}
	if net.ParseIP(host) != nil {
		return errors.New("ACME requires a real domain name, not a bare IP address")
	}
	if strings.Contains(host, "://") {
		return errors.New("domain must be stored without a URL scheme")
	}
	return nil
}

func validateNodeConfigPayload(body json.RawMessage) error {
	if len(body) == 0 {
		return nil
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("node config must be valid JSON: %w", err)
	}
	if payloadMap, ok := payload.(map[string]any); ok {
		if err := validateNodeInboundOverrides(payloadMap); err != nil {
			return err
		}
	}
	var problems []string
	validateNodeConfigValue(payload, "", &problems)
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateNodeInboundOverrides(payload map[string]any) error {
	rawInbounds, ok := payload["inbounds"].([]any)
	if !ok {
		return nil
	}
	for _, raw := range rawInbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		inboundType := strings.ToLower(strings.TrimSpace(fmt.Sprint(inbound["type"])))
		tag := strings.TrimSpace(fmt.Sprint(inbound["tag"]))
		switch inboundType {
		case "shadowsocks", "shadowtls", "vless":
			return fmt.Errorf("node-local overrides must not redefine %s inbounds directly; keep these protocols in global config and use tag-based partial patches only", inboundType)
		case "":
			switch tag {
			case "shadowtls-in", "ss-in", "vless-in":
				// Allowed: partial override object that patches the global inbound by tag.
			}
		}
	}
	return nil
}

func validateNodeConfigValue(value any, path string, problems *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			if key == "udp_over_tcp" {
				*problems = append(*problems, fmt.Sprintf("%s is not supported by the current sing-box runtime", nextPath))
			}
			if key == "type" && pathHasSuffix(path, "transport") {
				if transport := fmt.Sprint(nested); strings.EqualFold(transport, "xhttp") {
					*problems = append(*problems, fmt.Sprintf("%s xhttp is not supported by the current sing-box runtime", nextPath))
				}
			}
			validateNodeConfigValue(nested, nextPath, problems)
		}
	case []any:
		for index, nested := range typed {
			validateNodeConfigValue(nested, fmt.Sprintf("%s[%d]", path, index), problems)
		}
	}
}

func pathHasSuffix(path, suffix string) bool {
	if path == suffix {
		return true
	}
	return strings.HasSuffix(path, "."+suffix)
}

func clientIPFromRequest(r *http.Request) string {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		raw := strings.TrimSpace(r.Header.Get(header))
		if raw == "" {
			continue
		}
		if header == "X-Forwarded-For" {
			parts := strings.Split(raw, ",")
			raw = strings.TrimSpace(parts[0])
		}
		if raw != "" {
			return raw
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func deviceIdentifierFromRequest(r *http.Request) (string, string) {
	queryKeys := []string{
		"hwid", "HWID", "device_id", "deviceId", "device", "device_name",
		"client_id", "clientId", "client", "sub_id", "subid", "sid", "id",
	}
	for _, key := range queryKeys {
		if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
			return truncateValue(value, 256), "query:" + key
		}
	}
	headerKeys := []string{
		"X-HWID", "X-Hwid", "X-Device-ID", "X-Device-Id", "X-Device",
		"X-Client-ID", "X-Client-Id", "X-Client", "Client-ID", "Device-ID",
	}
	for _, key := range headerKeys {
		if value := strings.TrimSpace(r.Header.Get(key)); value != "" {
			return truncateValue(value, 256), "header:" + http.CanonicalHeaderKey(key)
		}
	}
	return "", ""
}

func subscriptionQueryParams(r *http.Request) map[string][]string {
	out := map[string][]string{}
	for key, values := range r.URL.Query() {
		if key == "" {
			continue
		}
		copied := make([]string, 0, len(values))
		for _, value := range values {
			copied = append(copied, truncateValue(value, 512))
		}
		out[key] = copied
	}
	return out
}

func subscriptionHeaders(r *http.Request) map[string]string {
	allow := []string{
		"User-Agent", "X-HWID", "X-Hwid", "X-Device-ID", "X-Device-Id", "X-Device",
		"X-Client-ID", "X-Client-Id", "X-Client", "Client-ID", "Device-ID",
		"X-Requested-With", "Accept", "Accept-Language", "CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For",
	}
	out := map[string]string{}
	for _, key := range allow {
		value := strings.TrimSpace(r.Header.Get(key))
		if value != "" {
			out[http.CanonicalHeaderKey(key)] = truncateValue(value, 512)
		}
	}
	return out
}

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}

func requestFingerprint(clientIP, userAgent, rawQuery string, headers json.RawMessage) string {
	return stableHash(strings.Join([]string{
		clientIP,
		userAgent,
		rawQuery,
		string(headers),
	}, "\x00"))
}

func stableHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func truncateValue(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}
