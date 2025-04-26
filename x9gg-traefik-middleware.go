package x9gg_traefik_middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/segmentio/ksuid"
)

const defaultHeaderName = "X-Trace-Id"

type Config struct {
	ValuePrefix   string `json:"valuePrefix"`
	ValueSuffix   string `json:"valueSuffix"`
	HeaderName    string `json:"headerName"`
	AddToResponse bool   `json:"addToResponse"`
}

func CreateConfig() *Config {
	return &Config{
		ValuePrefix:   "",
		ValueSuffix:   "",
		HeaderName:    defaultHeaderName,
		AddToResponse: true,
	}
}

type X9GGTraefikMiddleware struct {
	valuePrefix   string
	valueSuffix   string
	headerName    string
	addToResponse bool
	name          string
	next          http.Handler
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	middleware := &X9GGTraefikMiddleware{
		valuePrefix:   config.ValuePrefix,
		valueSuffix:   config.ValueSuffix,
		headerName:    config.HeaderName,
		addToResponse: config.AddToResponse,
		next:          next,
		name:          name,
	}

	if middleware.headerName == "" {
		middleware.headerName = defaultHeaderName
	}

	if middleware.valuePrefix == "\"\"" {
		middleware.valuePrefix = ""
	}

	if middleware.valueSuffix == "\"\"" {
		middleware.valueSuffix = ""
	}

	return middleware, nil
}

func (t *X9GGTraefikMiddleware) GenerateTraceId() string {
	id := ksuid.New()
	return t.valuePrefix + id.String() + t.valueSuffix
}

func (t *X9GGTraefikMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	traceValue := t.GenerateTraceId()
	req.Header.Set(t.headerName, traceValue)

	if t.addToResponse {
		rw.Header().Set(t.headerName, traceValue)
	}

	t.next.ServeHTTP(rw, req)
}
