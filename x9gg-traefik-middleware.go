package x9gg_traefik_middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/segmentio/ksuid"
)

const defaultTraceHeaderName = "X-Request-Trace-Id"

const defaultAuthServiceKeyNameHeaderName = "X-Service-Key-name"
const defaultAuthServiceKeyValueHeaderName = "X-Service-Key-Value"

type TraceConfig struct {
	Enabled       bool   `json:"enabled"`
	ValuePrefix   string `json:"valuePrefix"`
	ValueSuffix   string `json:"valueSuffix"`
	HeaderName    string `json:"headerName"`
	AddToResponse bool   `json:"addToResponse"`
}

type AuthConfig struct {
	Enabled                 bool         `json:"enabled"`
	KeyNameHeaderName       string       `json:"keyNameHeaderName"`
	KeyValueHeaderName      string       `json:"keyValueHeaderName"`
	RemoveKeyNameOnSuccess  bool         `json:"removeKeyNameOnSuccess"`
	RemoveKeyValueOnSuccess bool         `json:"removeKeyValueOnSuccess"`
	Keys                    []ServiceKey `json:"keys,omitempty"`
}

type ServiceKey struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Config struct {
	Trace TraceConfig `json:"trace"`
	Auth  AuthConfig  `json:"auth"`
}

type X9GGTraefikMiddleware struct {
	// Trace config
	traceEnabled       bool
	traceValuePrefix   string
	traceValueSuffix   string
	traceHeaderName    string
	traceAddToResponse bool

	// auth properties
	authEnabled             bool
	authKeyNameHeaderName   string
	authKeyValueHeaderName  string
	removeKeyNameOnSuccess  bool
	removeKeyValueOnSuccess bool
	keys                    map[string]string

	next http.Handler
}

func CreateConfig() *Config {
	return &Config{
		Trace: TraceConfig{
			Enabled:       true,
			ValuePrefix:   "",
			ValueSuffix:   "",
			HeaderName:    defaultTraceHeaderName,
			AddToResponse: true,
		},
		Auth: AuthConfig{
			Enabled:                 false,
			KeyNameHeaderName:       defaultAuthServiceKeyNameHeaderName,
			KeyValueHeaderName:      defaultAuthServiceKeyValueHeaderName,
			RemoveKeyNameOnSuccess:  false,
			RemoveKeyValueOnSuccess: true,
			Keys:                    make([]ServiceKey, 0),
		},
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Auth.Enabled && len(config.Auth.Keys) == 0 {
		return nil, fmt.Errorf("when auth is enabled, keys cannot be empty. Please specify at least one service key")
	}

	middleware := &X9GGTraefikMiddleware{
		traceEnabled:       config.Trace.Enabled,
		traceValuePrefix:   config.Trace.ValuePrefix,
		traceValueSuffix:   config.Trace.ValueSuffix,
		traceHeaderName:    config.Trace.HeaderName,
		traceAddToResponse: config.Trace.AddToResponse,

		authEnabled:             config.Auth.Enabled,
		authKeyNameHeaderName:   config.Auth.KeyNameHeaderName,
		authKeyValueHeaderName:  config.Auth.KeyValueHeaderName,
		removeKeyNameOnSuccess:  config.Auth.RemoveKeyNameOnSuccess,
		removeKeyValueOnSuccess: config.Auth.RemoveKeyValueOnSuccess,
		keys:                    make(map[string]string),

		next: next,
	}

	if middleware.traceEnabled {

		if middleware.traceHeaderName == "" {
			middleware.traceHeaderName = defaultTraceHeaderName
		}

		if middleware.traceValuePrefix == "\"\"" {
			middleware.traceValuePrefix = ""
		}

		if middleware.traceValueSuffix == "\"\"" {
			middleware.traceValueSuffix = ""
		}
	}

	if middleware.authEnabled {
		if middleware.authKeyNameHeaderName == "" {
			middleware.authKeyNameHeaderName = defaultAuthServiceKeyNameHeaderName
		}

		if middleware.authKeyValueHeaderName == "" {
			middleware.authKeyValueHeaderName = defaultAuthServiceKeyValueHeaderName
		}

		for _, key := range config.Auth.Keys {
			if key.Name == "" || key.Value == "" {
				return nil, fmt.Errorf("key name and value cannot be empty")
			}
			middleware.keys[key.Name] = key.Value
		}

	}
	return middleware, nil
}

func (m *X9GGTraefikMiddleware) isKeyPairValid(keyName string, keyValue string) bool {
	if keyName == "" || keyValue == "" {
		return false
	}

	if m.keys == nil {
		return false
	}

	value, exists := m.keys[keyName]

	if exists && value == keyValue {
		return true
	}
	return false
}

func (m *X9GGTraefikMiddleware) GenerateTraceId() string {
	id := ksuid.New()
	return m.traceValuePrefix + id.String() + m.traceValueSuffix
}

func (m *X9GGTraefikMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.traceEnabled {
		traceValue := m.GenerateTraceId()
		req.Header.Set(m.traceHeaderName, traceValue)

		if m.traceAddToResponse {
			rw.Header().Set(m.traceHeaderName, traceValue)
		}
	}

	if m.authEnabled {
		keyName := req.Header.Get(m.authKeyNameHeaderName)
		keyValue := req.Header.Get(m.authKeyValueHeaderName)

		authenticated := m.isKeyPairValid(keyName, keyValue)

		if !authenticated {
			rw.Header().Set("Content-Type", "application/plain; charset=utf-8")
			rw.WriteHeader(http.StatusUnauthorized)

			// TODO: custom error response
			return
		}

		if m.removeKeyNameOnSuccess {
			req.Header.Del(m.authKeyNameHeaderName)
		}

		if m.removeKeyValueOnSuccess {
			req.Header.Del(m.authKeyValueHeaderName)
		}
	}

	m.next.ServeHTTP(rw, req)
}
