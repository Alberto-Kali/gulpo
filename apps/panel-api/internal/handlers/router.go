package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
			Tags              []string              `json:"tags"`
			AllowedNodeIDs    []string              `json:"allowed_node_ids"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		user, err := a.store.CreateUser(r.Context(), domain.User{
			ExternalID:        req.ExternalID,
			Name:              req.Name,
			Status:            req.Status,
			TrafficLimitBytes: req.TrafficLimitBytes,
			NodeAccessMode:    req.NodeAccessMode,
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
			ExternalID:        current.ExternalID,
			Name:              current.Name,
			Status:            current.Status,
			TrafficLimitBytes: current.TrafficLimitBytes,
			NodeAccessMode:    current.NodeAccessMode,
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
	profiles, err := a.store.BuildProfilePage(r.Context(), user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, profiles)
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
