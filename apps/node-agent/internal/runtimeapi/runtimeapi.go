package runtimeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	statscmd "github.com/v2fly/v2ray-core/v5/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	v2rayListen string
	clashURL    string
	httpClient  *http.Client
}

type UserTrafficSample struct {
	UplinkBytes   int64
	DownlinkBytes int64
}

type SessionPresence struct {
	UserID      string
	Protocol    string
	Connections int
}

func New(v2rayListen, clashURL string) *Client {
	return &Client{
		v2rayListen: v2rayListen,
		clashURL:    strings.TrimRight(clashURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) FetchTrafficCounters(ctx context.Context) (map[string]UserTrafficSample, error) {
	conn, err := grpc.DialContext(ctx, c.v2rayListen, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	statsClient := statscmd.NewStatsServiceClient(conn)
	resp, err := statsClient.QueryStats(ctx, &statscmd.QueryStatsRequest{
		Patterns: []string{"user>>>"},
		Regexp:   false,
	})
	if err != nil {
		return nil, err
	}
	out := map[string]UserTrafficSample{}
	for _, stat := range resp.GetStat() {
		userID, direction, ok := parseUserTrafficStatName(stat.GetName())
		if !ok || userID == "" {
			continue
		}
		sample := out[userID]
		switch direction {
		case "uplink":
			sample.UplinkBytes = stat.GetValue()
		case "downlink":
			sample.DownlinkBytes = stat.GetValue()
		}
		out[userID] = sample
	}
	return out, nil
}

func (c *Client) FetchSessionSnapshot(ctx context.Context) ([]SessionPresence, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.clashURL+"/connections", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected clash api status: %s", resp.Status)
	}
	var payload struct {
		Connections []map[string]any `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	counter := map[string]int{}
	for _, connection := range payload.Connections {
		metadata := connection
		if nested, ok := connection["metadata"].(map[string]any); ok {
			metadata = nested
		}
		userID := firstString(metadata,
			"inboundUser",
			"inbound_user",
			"user",
			"authUser",
			"auth_user",
			"email",
		)
		if userID == "" {
			continue
		}
		protocol := detectProtocol(metadata)
		if protocol == "" {
			continue
		}
		counter[userID+":"+protocol]++
	}
	out := make([]SessionPresence, 0, len(counter))
	for key, connections := range counter {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, SessionPresence{
			UserID:      parts[0],
			Protocol:    parts[1],
			Connections: connections,
		})
	}
	return out, nil
}

func parseUserTrafficStatName(name string) (userID, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

func firstString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			if typed, ok := value.(string); ok && typed != "" {
				return typed
			}
		}
	}
	return ""
}

func detectProtocol(metadata map[string]any) string {
	for _, candidate := range []string{
		firstString(metadata, "inbound", "inboundTag", "inbound_tag", "inboundName", "inbound_name"),
		firstString(metadata, "type"),
		firstString(metadata, "network"),
	} {
		switch {
		case strings.Contains(candidate, "shadowtls"):
			return "shadowsocks"
		case strings.Contains(candidate, "ss"):
			return "shadowsocks"
		case strings.Contains(candidate, "trojan"):
			return "trojan"
		case strings.Contains(candidate, "vless"):
			return "vless"
		case strings.Contains(candidate, "hysteria2"):
			return "hysteria2"
		case strings.Contains(candidate, "tuic"):
			return "tuic"
		}
	}
	return ""
}
