package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
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
	mux.HandleFunc("/api/admin/login", api.handleAdminLogin)
	mux.HandleFunc("/api/subscriptions/", api.handleSubscription)
	mux.HandleFunc("/api/node/enroll", api.handleNodeEnroll)
	mux.HandleFunc("/api/node/heartbeat", api.handleNodeHeartbeat)
	mux.HandleFunc("/api/node/sync", api.handleNodeSync)
	mux.HandleFunc("/api/node/usage/batch", api.handleNodeUsageBatch)

	mux.Handle("/api/admin/users", api.adminAuth(http.HandlerFunc(api.handleUsers)))
	mux.Handle("/api/admin/users/", api.adminAuth(http.HandlerFunc(api.handleUserByID)))
	mux.Handle("/api/admin/nodes", api.adminAuth(http.HandlerFunc(api.handleNodes)))
	mux.Handle("/api/admin/nodes/", api.adminAuth(http.HandlerFunc(api.handleNodeByID)))
	mux.Handle("/api/admin/config/global", api.adminAuth(http.HandlerFunc(api.handleGlobalConfig)))

	return withCORS(mux)
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

func (a *API) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	admin, err := a.store.GetAdminByEmail(r.Context(), req.Email)
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
			ExternalID        *string                `json:"external_id"`
			Name              string                 `json:"name"`
			Status            domain.UserStatus      `json:"status"`
			TrafficLimitBytes int64                  `json:"traffic_limit_bytes"`
			NodeAccessMode    domain.NodeAccessMode  `json:"node_access_mode"`
			Tags              []string               `json:"tags"`
			AllowedNodeIDs    []string               `json:"allowed_node_ids"`
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
		var req struct{ Tags []string `json:"tags"` }
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
			Name              string                 `json:"name"`
			Status            domain.UserStatus      `json:"status"`
			TrafficLimitBytes int64                  `json:"traffic_limit_bytes"`
			NodeAccessMode    domain.NodeAccessMode  `json:"node_access_mode"`
			AllowedNodeIDs    []string               `json:"allowed_node_ids"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		user, err := a.store.UpdateUser(r.Context(), id, domain.User{
			ExternalID: req.ExternalID,
			Name: req.Name,
			Status: req.Status,
			TrafficLimitBytes: req.TrafficLimitBytes,
			NodeAccessMode: req.NodeAccessMode,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_ = a.store.ReplaceAllowedNodes(r.Context(), id, req.AllowedNodeIDs)
		user.AllowedNodeIDs = req.AllowedNodeIDs
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
			Status              domain.NodeStatus          `json:"status"`
			DefaultAccessPolicy domain.DefaultAccessPolicy `json:"default_access_policy"`
			DefaultAccessTag    *string                    `json:"default_access_tag"`
			AgentVersion        string                     `json:"agent_version"`
			SingboxVersion      string                     `json:"singbox_version"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		node, err := a.store.CreateNode(r.Context(), domain.Node{
			Name: req.Name,
			Domain: req.Domain,
			Status: req.Status,
			DefaultAccessPolicy: req.DefaultAccessPolicy,
			DefaultAccessTag: req.DefaultAccessTag,
			AgentVersion: req.AgentVersion,
			SingboxVersion: req.SingboxVersion,
			ConfigOverride: []byte(`{}`),
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
			Type    domain.CommandType  `json:"type"`
			Payload map[string]any      `json:"payload"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		payload, _ := json.Marshal(req.Payload)
		cmd, err := a.store.CreateNodeCommand(r.Context(), domain.NodeCommand{
			NodeID: id,
			Type: req.Type,
			Payload: payload,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, cmd)
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
			Name                string                     `json:"name"`
			Domain              string                     `json:"domain"`
			Status              domain.NodeStatus          `json:"status"`
			DefaultAccessPolicy domain.DefaultAccessPolicy `json:"default_access_policy"`
			DefaultAccessTag    *string                    `json:"default_access_tag"`
			AgentVersion        string                     `json:"agent_version"`
			SingboxVersion      string                     `json:"singbox_version"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		node, err := a.store.UpdateNode(r.Context(), id, domain.Node{
			Name: req.Name,
			Domain: req.Domain,
			Status: req.Status,
			DefaultAccessPolicy: req.DefaultAccessPolicy,
			DefaultAccessTag: req.DefaultAccessTag,
			AgentVersion: req.AgentVersion,
			SingboxVersion: req.SingboxVersion,
		})
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
	cfg, _ := a.store.GetGlobalConfig(r.Context())
	var desired map[string]any
	_ = json.Unmarshal(cfg.ConfigJSON, &desired)
	if len(node.ConfigOverride) > 0 {
		var override map[string]any
		_ = json.Unmarshal(node.ConfigOverride, &override)
		for k, v := range override {
			desired[k] = v
		}
	}
	commands, _ := a.store.ListPendingNodeCommands(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, domain.EnrollResponse{
		NodeID: node.ID,
		NodeAPIKey: node.APIKey,
		DesiredConfig: desired,
		Commands: commands,
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
		AgentVersion    string `json:"agent_version"`
		SingboxVersion  string `json:"singbox_version"`
		CommandResults  []struct {
			ID      string                `json:"id"`
			Status  domain.CommandStatus  `json:"status"`
			Result  string                `json:"result"`
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
	globalCfg, _ := a.store.GetGlobalConfig(r.Context())
	var desired map[string]any
	_ = json.Unmarshal(globalCfg.ConfigJSON, &desired)
	if len(node.ConfigOverride) > 0 {
		var override map[string]any
		_ = json.Unmarshal(node.ConfigOverride, &override)
		for k, v := range override {
			desired[k] = v
		}
	}
	commands, _ := a.store.ListPendingNodeCommands(r.Context(), node.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": node.ID,
		"desired_config": desired,
		"commands": commands,
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
