package x9gg_traefik_middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/segmentio/ksuid"
)

const defaultTraceHeaderName = "X-Request-Trace-Id"

type TraceConfig struct {
	Enabled       bool   `json:"enabled"`
	ValuePrefix   string `json:"valuePrefix"`
	ValueSuffix   string `json:"valueSuffix"`
	HeaderName    string `json:"headerName"`
	AddToResponse bool   `json:"addToResponse"`
}

type Config struct {
	Trace TraceConfig `json:"trace"`
}

type X9GGTraefikMiddleware struct {
	traceEnabled       bool
	traceValuePrefix   string
	traceValueSuffix   string
	traceHeaderName    string
	traceAddToResponse bool

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
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	middleware := &X9GGTraefikMiddleware{
		traceEnabled:       config.Trace.Enabled,
		traceValuePrefix:   config.Trace.ValuePrefix,
		traceValueSuffix:   config.Trace.ValueSuffix,
		traceHeaderName:    config.Trace.HeaderName,
		traceAddToResponse: config.Trace.AddToResponse,

		next: next,
	}

	if middleware.traceHeaderName == "" {
		middleware.traceHeaderName = defaultTraceHeaderName
	}

	if middleware.traceValuePrefix == "\"\"" {
		middleware.traceValuePrefix = ""
	}

	if middleware.traceValueSuffix == "\"\"" {
		middleware.traceValueSuffix = ""
	}

	return middleware, nil
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

	m.next.ServeHTTP(rw, req)
}
