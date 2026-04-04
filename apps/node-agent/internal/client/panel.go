package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

type Command struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

type EnrollResponse struct {
	NodeID        string         `json:"node_id"`
	NodeAPIKey    string         `json:"node_api_key"`
	DesiredConfig map[string]any `json:"desired_config"`
	Commands      []Command      `json:"commands"`
}

type SyncResponse struct {
	NodeID        string         `json:"node_id"`
	DesiredConfig map[string]any `json:"desired_config"`
	Commands      []Command      `json:"commands"`
}

func (c *Client) Enroll(ctx context.Context, token, agentVersion, singboxVersion string) (EnrollResponse, error) {
	return post[EnrollResponse](ctx, c.http, c.baseURL+"/api/node/enroll", "", map[string]string{}, map[string]string{
		"enroll_token": token,
		"agent_version": agentVersion,
		"singbox_version": singboxVersion,
	})
}

func (c *Client) Heartbeat(ctx context.Context, nodeKey, agentVersion, singboxVersion string) error {
	_, err := post[map[string]string](ctx, c.http, c.baseURL+"/api/node/heartbeat", nodeKey, map[string]string{}, map[string]string{
		"agent_version": agentVersion,
		"singbox_version": singboxVersion,
	})
	return err
}

func (c *Client) Sync(ctx context.Context, nodeKey, agentVersion, singboxVersion string, commandResults []map[string]any) (SyncResponse, error) {
	return post[SyncResponse](ctx, c.http, c.baseURL+"/api/node/sync", nodeKey, map[string]string{}, map[string]any{
		"agent_version": agentVersion,
		"singbox_version": singboxVersion,
		"command_results": commandResults,
	})
}

func (c *Client) UsageBatch(ctx context.Context, nodeKey string, records []map[string]any) error {
	_, err := post[map[string]string](ctx, c.http, c.baseURL+"/api/node/usage/batch", nodeKey, map[string]string{}, map[string]any{
		"records": records,
	})
	return err
}

func post[T any](ctx context.Context, client *http.Client, url string, nodeKey string, extraHeaders map[string]string, payload any) (T, error) {
	var zero T
	body, err := json.Marshal(payload)
	if err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	if nodeKey != "" {
		req.Header.Set("X-Node-Key", nodeKey)
	}
	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return zero, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	var decoded T
	err = json.NewDecoder(resp.Body).Decode(&decoded)
	return decoded, err
}

