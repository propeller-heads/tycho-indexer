# Observability Stack for Tycho Indexer

This setup provides comprehensive observability for Tycho Indexer using the Grafana LGTM stack with Promtail for log collection.

## Components

- **Loki**: Log aggregation and querying (port 3100)
- **Grafana**: Visualization and dashboards (port 3000)
- **Tempo**: Distributed tracing (via OTLP port 4317)
- **Mimir/Prometheus**: Metrics storage
- **Promtail**: Log collection agent for Docker containers

## Access

- **Grafana UI**: http://localhost:3000
  - Username: `admin`
  - Password: `admin`
- **Loki API**: http://localhost:3100 (for direct API access)

## Configuration

The `docker-compose.yaml` includes:

1. **LGTM Service**: The all-in-one observability stack with Loki enabled
2. **Promtail Service**: Collects logs only from tycho-indexer service and forwards to Loki
3. **OTLP Configuration**: Tycho-indexer sends traces to `http://lgtm:4317`
4. **Enhanced Logging**: JSON-file driver with proper labeling for tycho-indexer

## Viewing Logs

1. Access Grafana at http://localhost:3000
2. Navigate to Explore > Loki
3. Use LogQL queries to filter logs:
   ```logql
   # All tycho-indexer logs
   {service="tycho-indexer"}
   
   # Filter by log level
   {service="tycho-indexer"} |= "ERROR"
   {service="tycho-indexer"} |= "WARN" 
   {service="tycho-indexer"} |= "INFO"
   {service="tycho-indexer"} |= "DEBUG"
   
   # Filter by module
   {service="tycho-indexer"} |= "dynamic_contract_indexer"
   {service="tycho-indexer"} |= "hook_dci"
   {service="tycho-indexer"} |= "HookOrchestrator"
   
   # Filter by specific components
   {service="tycho-indexer"} |= "UniswapV4HookDCI"
   {service="tycho-indexer"} |= "metadata_orchestrator"
   
   # Search for errors in hooks processing
   {service="tycho-indexer"} |= "hooks" |= "error"
   
   # Filter by target (Rust module path)
   {service="tycho-indexer"} | json | target=~".*dynamic_contract_indexer.*"
   ```

## Viewing Traces

1. Navigate to Explore > Tempo
2. Search for traces by:
   - Trace ID
   - Service name: `tycho-indexer`
   - Duration range
   - Operation name (e.g. `process_block_update`, `initialize`)

## Docker Logs

For quick debugging, you can still use standard Docker commands:
```bash
# View tycho-indexer logs
docker-compose logs -f tycho-indexer

# View all logs
docker-compose logs -f

# View Promtail logs (log collection agent)
docker-compose logs -f promtail

# View LGTM stack logs
docker-compose logs -f lgtm
```

## Debug Logging

To enable debug logs for specific modules:
```bash
# Debug logs for all hooks modules
RUST_LOG="warn,tycho_indexer::extractor::dynamic_contract_indexer=debug" docker-compose up

# Debug logs for specific components
RUST_LOG="warn,tycho_indexer::extractor::dynamic_contract_indexer::hook_dci=debug" docker-compose up

# Trace level for maximum verbosity
RUST_LOG="warn,tycho_indexer::extractor::dynamic_contract_indexer=trace" docker-compose up
```

## Troubleshooting

### No Logs in Loki
1. Check if Promtail is running: `docker-compose logs promtail`
2. Verify Loki is accessible: `curl http://localhost:3100/ready`
3. Check tycho-indexer container labels: `docker inspect <container_id> | grep -A5 Labels`

### Missing Traces
1. Verify OTLP endpoint: Check `OTLP_EXPORTER_ENDPOINT` environment variable
2. Check Tempo readiness: Look for Tempo logs in LGTM container

### Log Parsing Issues
1. Check Promtail configuration: `docker-compose exec promtail cat /etc/promtail/config.yml`
2. View Promtail targets: `curl http://localhost:9080/targets`

## Notes

- **Data Persistence**: The LGTM stack stores data in the `lgtm_data` volume
- **Log Collection**: Promtail collects logs from Docker containers via JSON file driver
- **Tracing**: Traces are sent via OpenTelemetry Protocol (OTLP) directly from the application
- **Performance**: Logs are rotated (max 10MB, 3 files) to prevent disk space issues
- **Filtering**: Use LogQL in Grafana for powerful log filtering and analysis