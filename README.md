# X9GG Traefik Middleware

⚠️ **UNDER ACTIVE DEVELOPMENT** ⚠️ 

**Disclaimer:** This plugin is a work in progress and is not recommended for production environments without thorough testing. Use at your own risk.

## About

This plugin is a multi-purpose security and tracing middleware for Traefik that provides:

1. **Request Tracing** - Generate unique IDs for distributed tracing
2. **Service Authentication** - Validate API keys for service-to-service communication

## Quick Start

```yaml
# cli static config 

--experimental.plugins.x9gg-traefik-middleware.version=v0.2.0
--experimental.plugins.x9gg-traefik-middleware.modulename=github.com/x9gg/traefik-middleware

```


```yaml
# Dynamic configuration
http:
  middlewares:
    x9gg-traefik-middleware:
      plugin:
        x9gg-traefik-middleware:
          trace:
            enabled: true
            headerName: "X-Request-Trace-Id"
          auth:
            enabled: true
            removeKeyNameOnSuccess: false
            removeKeyValueOnSuccess: true
            keys:
              - name: "service-a" 
                value: "api-key-123"
```

## Features (TBD)


## Comming soon
- **IP Access Control** - Allow or deny requests based on IP address/range
- Custom response error

## Todos
- add tests

## License

[MIT License](LICENSE)