package store

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	secretcrypto "github.com/fear/gulpo/apps/panel-api/internal/crypto"
	"github.com/fear/gulpo/apps/panel-api/internal/domain"
)

func TestMergeMapMergesInboundArraysByTag(t *testing.T) {
	base := map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{
			map[string]any{"tag": "ss-in", "type": "shadowsocks", "listen_port": 2080},
			map[string]any{"tag": "vless-in", "type": "vless", "listen_port": 9443},
		},
	}
	override := map[string]any{
		"log": map[string]any{"level": "debug"},
		"inbounds": []any{
			map[string]any{"tag": "vless-in", "transport": map[string]any{"type": "grpc", "service_name": "gulpo-grpc"}},
			map[string]any{"tag": "trojan-in", "type": "trojan", "listen_port": 8443},
		},
	}

	got := mergeMap(base, override)
	inbounds, ok := got["inbounds"].([]any)
	if !ok || len(inbounds) != 3 {
		t.Fatalf("expected merged inbounds, got %#v", got["inbounds"])
	}
	if inbounds[1].(map[string]any)["type"] != "vless" {
		t.Fatalf("expected vless inbound to be preserved, got %#v", inbounds[1])
	}
	if inbounds[1].(map[string]any)["transport"].(map[string]any)["type"] != "grpc" {
		t.Fatalf("expected vless inbound override to merge by tag, got %#v", inbounds[1])
	}
	if inbounds[2].(map[string]any)["type"] != "trojan" {
		t.Fatalf("expected trojan inbound to be appended, got %#v", inbounds[2])
	}
	if got["log"].(map[string]any)["level"] != "debug" {
		t.Fatalf("expected nested map override")
	}
}

func TestNormalizeGlobalConfigJSONAddsDefaultVLESSAndShadowsocks(t *testing.T) {
	normalized, err := normalizeGlobalConfigJSON([]byte(`{"outbounds":[]}`))
	if err != nil {
		t.Fatalf("normalize global config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(normalized, &cfg); err != nil {
		t.Fatalf("unmarshal normalized global config: %v", err)
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) < 3 {
		t.Fatalf("expected default global inbounds, got %#v", cfg["inbounds"])
	}
	seen := map[string]bool{}
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		seen[asString(inbound["tag"])] = true
	}
	if !seen["shadowtls-in"] || !seen["ss-in"] || !seen["vless-in"] {
		t.Fatalf("expected default global shadowtls/ss/vless tags, got %#v", seen)
	}
}

func TestResolveNodeRuntimeConfigPatchesSupportedProtocols(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	ssPassword, err := box.Encrypt("ss-user-secret")
	if err != nil {
		t.Fatalf("encrypt ss: %v", err)
	}
	trojanPassword, err := box.Encrypt("trojan-user-secret")
	if err != nil {
		t.Fatalf("encrypt trojan: %v", err)
	}
	hy2Password, err := box.Encrypt("hy2-user-secret")
	if err != nil {
		t.Fatalf("encrypt hy2: %v", err)
	}
	tuicPassword, err := box.Encrypt("tuic-user-secret")
	if err != nil {
		t.Fatalf("encrypt tuic: %v", err)
	}

	store := &PostgresStore{secrets: box}
	node := domain.Node{Domain: "edge.example.com", CertificateMode: domain.CertificateModeACME}
	cfg := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "shadowtls",
				"listen_port": 2443,
			},
			map[string]any{
				"type":        "shadowsocks",
				"listen_port": 2081,
				"method":      "aes-128-gcm",
			},
			map[string]any{
				"type":        "trojan",
				"listen_port": 8443,
				"tls": map[string]any{
					"enabled": true,
					"acme": map[string]any{
						"enabled": true,
					},
				},
			},
			map[string]any{
				"type":        "vless",
				"listen_port": 9443,
				"transport": map[string]any{
					"type":         "grpc",
					"service_name": "gulpo-grpc",
				},
				"tls": map[string]any{
					"enabled": true,
					"reality": map[string]any{
						"public_key": "pubkey",
						"short_id":   "abcd",
					},
				},
			},
			map[string]any{
				"type":        "hysteria2",
				"listen_port": 9444,
			},
			map[string]any{
				"type":        "tuic",
				"listen_port": 9445,
			},
		},
	}
	users := []domain.User{{
		ID:                         "user-1",
		SSPasswordEncrypted:        ssPassword,
		TrojanPasswordEncrypted:    trojanPassword,
		VLESSUUID:                  "0f8fad5b-d9cb-469f-a165-70867728950e",
		Hysteria2PasswordEncrypted: hy2Password,
		TUICUUID:                   "7f8fad5b-d9cb-469f-a165-70867728950e",
		TUICPasswordEncrypted:      tuicPassword,
	}}

	got, err := store.resolveNodeRuntimeConfig(node, cfg, users)
	if err != nil {
		t.Fatalf("resolve runtime config: %v", err)
	}
	inbounds := got["inbounds"].([]any)

	shadowTLSInbound := inbounds[0].(map[string]any)
	shadowTLSUsers := shadowTLSInbound["users"].([]map[string]any)
	if len(shadowTLSUsers) != 1 || shadowTLSUsers[0]["password"] != "ss-user-secret" {
		t.Fatalf("expected generated shadowtls user, got %#v", shadowTLSUsers)
	}
	shadowTLSHandshake := shadowTLSInbound["handshake"].(map[string]any)
	if shadowTLSHandshake["server"] != "www.gosuslugi.ru" {
		t.Fatalf("expected default shadowtls mask host, got %#v", shadowTLSHandshake["server"])
	}

	ssUsers := inbounds[1].(map[string]any)["users"].([]map[string]any)
	if len(ssUsers) != 1 || ssUsers[0]["password"] != "ss-user-secret" {
		t.Fatalf("expected generated shadowsocks user, got %#v", ssUsers)
	}

	trojanInbound := inbounds[2].(map[string]any)
	trojanUsers := trojanInbound["users"].([]map[string]any)
	if len(trojanUsers) != 1 || trojanUsers[0]["password"] != "trojan-user-secret" {
		t.Fatalf("expected generated trojan user, got %#v", trojanUsers)
	}
	tlsConfig := trojanInbound["tls"].(map[string]any)
	if tlsConfig["server_name"] != "edge.example.com" {
		t.Fatalf("expected default tls server_name, got %#v", tlsConfig["server_name"])
	}
	acmeConfig := tlsConfig["acme"].(map[string]any)
	domains := acmeConfig["domain"].([]string)
	if len(domains) != 1 || domains[0] != "edge.example.com" {
		t.Fatalf("expected default acme domain, got %#v", acmeConfig["domain"])
	}
	if acmeConfig["data_directory"] != "__GULPO_ACME_DATA_DIR__" {
		t.Fatalf("expected acme data dir placeholder, got %#v", acmeConfig["data_directory"])
	}
	if gotALPN := tlsConfig["alpn"].([]string); len(gotALPN) != 2 || gotALPN[0] != "h2" {
		t.Fatalf("expected trojan ALPN defaults, got %#v", gotALPN)
	}

	vlessInbound := inbounds[3].(map[string]any)
	vlessUsers := vlessInbound["users"].([]map[string]any)
	if len(vlessUsers) != 1 || vlessUsers[0]["uuid"] != "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Fatalf("expected generated vless user, got %#v", vlessUsers)
	}
	if vlessUsers[0]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("expected vless flow, got %#v", vlessUsers[0]["flow"])
	}
	realityHandshake := vlessInbound["tls"].(map[string]any)["reality"].(map[string]any)["handshake"].(map[string]any)
	if realityHandshake["server"] != "www.gosuslugi.ru" {
		t.Fatalf("expected reality handshake mask host, got %#v", realityHandshake["server"])
	}

	hy2Users := inbounds[4].(map[string]any)["users"].([]map[string]any)
	if len(hy2Users) != 1 || hy2Users[0]["password"] != "hy2-user-secret" {
		t.Fatalf("expected generated hysteria2 user, got %#v", hy2Users)
	}

	tuicUsers := inbounds[5].(map[string]any)["users"].([]map[string]any)
	if len(tuicUsers) != 1 || tuicUsers[0]["password"] != "tuic-user-secret" {
		t.Fatalf("expected generated tuic user, got %#v", tuicUsers)
	}
}

func TestBuildNodeProfilesPrefersShadowTLSAndRealityDetails(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	ssPassword, _ := box.Encrypt("ss-user-secret")
	hy2Password, _ := box.Encrypt("hy2-user-secret")

	node := domain.Node{
		ID:     "node-1",
		Name:   "edge-node",
		Domain: "edge.example.com",
		Status: domain.NodeStatusOnline,
	}
	user := domain.User{
		ID:                         "user-1",
		Name:                       "user-1",
		SSPasswordEncrypted:        ssPassword,
		VLESSUUID:                  "0f8fad5b-d9cb-469f-a165-70867728950e",
		Hysteria2PasswordEncrypted: hy2Password,
	}
	cfg := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "shadowtls",
				"listen_port": 2443,
				"handshake":   map[string]any{"server": "www.gosuslugi.ru", "server_port": 443},
			},
			map[string]any{
				"type":        "shadowsocks",
				"listen_port": 2081,
				"method":      "aes-128-gcm",
			},
			map[string]any{
				"type":        "vless",
				"listen_port": 9443,
				"transport": map[string]any{
					"type":         "grpc",
					"service_name": "gulpo-grpc",
				},
				"tls": map[string]any{
					"enabled": true,
					"reality": map[string]any{
						"fingerprint": "chrome",
						"public_key":  "pubkey",
						"short_id":    []any{"abcd"},
						"handshake":   map[string]any{"server": "www.gosuslugi.ru", "server_port": 443},
					},
				},
			},
			map[string]any{
				"type":        "hysteria2",
				"listen_port": 8444,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": "edge.example.com",
				},
				"obfs": map[string]any{
					"type":     "salamander",
					"password": "mask-secret",
				},
			},
		},
	}

	profiles := buildNodeProfilesForUser(node, cfg, user, nil, box)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %#v", profiles)
	}
	if profiles[0].Protocol != "shadowsocks" || profiles[0].TransportMode != "shadowtls" {
		t.Fatalf("expected shadowtls-backed shadowsocks profile, got %#v", profiles[0])
	}
	if !strings.Contains(profiles[0].URI, "plugin=shadow-tls") {
		t.Fatalf("expected shadowtls plugin URI, got %s", profiles[0].URI)
	}
	if profiles[1].Protocol != "vless" || profiles[1].Flow != "xtls-rprx-vision" || profiles[1].MaskHost != "www.gosuslugi.ru" {
		t.Fatalf("expected reality profile metadata, got %#v", profiles[1])
	}
	if profiles[1].TransportMode != "grpc" {
		t.Fatalf("expected grpc transport mode, got %#v", profiles[1].TransportMode)
	}
	if !strings.Contains(profiles[1].URI, "type=grpc") || !strings.Contains(profiles[1].URI, "serviceName=gulpo-grpc") {
		t.Fatalf("expected grpc vless uri, got %s", profiles[1].URI)
	}
	if profiles[2].Protocol != "hysteria2" || profiles[2].Obfs != "salamander" {
		t.Fatalf("expected hysteria2 obfs metadata, got %#v", profiles[2])
	}
	if !strings.HasPrefix(profiles[2].URI, "hysteria2://") {
		t.Fatalf("expected hysteria2 URI scheme, got %s", profiles[2].URI)
	}
}

func TestBuildNodeProfilesUsesStaticShadowTLSV2PasswordInURI(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	ssPassword, _ := box.Encrypt("ss-user-secret")

	node := domain.Node{
		ID:     "node-1",
		Name:   "edge-node",
		Domain: "edge.example.com",
		Status: domain.NodeStatusOnline,
	}
	user := domain.User{
		ID:                  "user-1",
		Name:                "user-1",
		SSPasswordEncrypted: ssPassword,
	}
	cfg := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "shadowtls",
				"listen_port": 2443,
				"version":     2,
				"password":    "node-shadowtls-secret",
				"handshake":   map[string]any{"server": "www.gosuslugi.ru", "server_port": 443},
			},
			map[string]any{
				"type":        "shadowsocks",
				"listen_port": 2081,
				"method":      "aes-128-gcm",
			},
		},
	}

	profiles := buildNodeProfilesForUser(node, cfg, user, nil, box)
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %#v", profiles)
	}
	if !strings.Contains(profiles[0].URI, "password%3Dnode-shadowtls-secret") {
		t.Fatalf("expected shadowtls plugin to use node password, got %s", profiles[0].URI)
	}
	if strings.Contains(profiles[0].URI, "password%3Dss-user-secret") {
		t.Fatalf("expected shadowtls plugin to avoid user secret in plugin password, got %s", profiles[0].URI)
	}
}

func TestResolveNodeRuntimeConfigKeepsShadowTLSV2Password(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	ssPassword, err := box.Encrypt("ss-user-secret")
	if err != nil {
		t.Fatalf("encrypt ss: %v", err)
	}

	store := &PostgresStore{secrets: box}
	node := domain.Node{Domain: "edge.example.com", CertificateMode: domain.CertificateModeACME}
	cfg := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "shadowtls",
				"listen_port": 2443,
				"version":     2,
				"password":    "node-shadowtls-secret",
			},
			map[string]any{
				"type":        "shadowsocks",
				"listen_port": 2081,
				"method":      "aes-128-gcm",
			},
			map[string]any{
				"type":        "vless",
				"listen_port": 9443,
				"tls": map[string]any{
					"enabled": true,
					"reality": map[string]any{
						"private_key": "II4u6hmqKqd2l-oEGNuZZrJGaS1zuRlLQf-TXPDubUI",
						"short_id":    "abcd1234",
					},
				},
			},
		},
	}
	users := []domain.User{{
		ID:                  "user-1",
		SSPasswordEncrypted: ssPassword,
		VLESSUUID:           "0f8fad5b-d9cb-469f-a165-70867728950e",
	}}

	got, err := store.resolveNodeRuntimeConfig(node, cfg, users)
	if err != nil {
		t.Fatalf("resolve runtime config: %v", err)
	}
	inbounds := got["inbounds"].([]any)

	shadowTLSInbound := inbounds[0].(map[string]any)
	if shadowTLSInbound["password"] != "node-shadowtls-secret" {
		t.Fatalf("expected shadowtls v2 password to be preserved, got %#v", shadowTLSInbound["password"])
	}
	if _, exists := shadowTLSInbound["users"]; exists {
		t.Fatalf("expected shadowtls v2 to avoid runtime users, got %#v", shadowTLSInbound["users"])
	}
}

func TestEnsureSecretFieldsGeneratesBase64ShadowsocksSecret(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	store := &PostgresStore{secrets: box}
	user := &domain.User{}

	if err := store.ensureSecretFields(user); err != nil {
		t.Fatalf("ensure secret fields: %v", err)
	}
	if user.SSPasswordEncrypted == "" {
		t.Fatal("expected encrypted ss password")
	}
	plain, err := box.Decrypt(user.SSPasswordEncrypted)
	if err != nil {
		t.Fatalf("decrypt ss password: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(plain)
	if err != nil {
		t.Fatalf("expected base64 ss password, got %q: %v", plain, err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte ss password, got %d", len(raw))
	}
}

func TestEnsureUserSecretsRotatesLegacyShadowsocksSecret(t *testing.T) {
	box := secretcrypto.NewSecretBox("test-secret")
	legacySS, err := box.Encrypt("legacy-hex-like-secret")
	if err != nil {
		t.Fatalf("encrypt legacy ss password: %v", err)
	}
	store := &PostgresStore{secrets: box}
	user := &domain.User{
		ID:                         "user-1",
		SSPasswordEncrypted:        legacySS,
		TrojanPasswordEncrypted:    "keep",
		VLESSUUID:                  "0f8fad5b-d9cb-469f-a165-70867728950e",
		Hysteria2PasswordEncrypted: "keep",
		TUICUUID:                   "7f8fad5b-d9cb-469f-a165-70867728950e",
		TUICPasswordEncrypted:      "keep",
	}

	if !store.ssSecretNeedsRotation(user.SSPasswordEncrypted) {
		t.Fatal("expected legacy ss secret to require rotation")
	}
	user.SSPasswordEncrypted = ""
	if err := store.ensureSecretFields(user); err != nil {
		t.Fatalf("ensure secret fields: %v", err)
	}
	plain, err := box.Decrypt(user.SSPasswordEncrypted)
	if err != nil {
		t.Fatalf("decrypt rotated ss password: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(plain)
	if err != nil {
		t.Fatalf("expected rotated ss password to be base64, got %q: %v", plain, err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte rotated ss password, got %d", len(raw))
	}
}
