# Metrics and Observability

This document describes the metrics collection infrastructure for tycho-integration-test.

## Overview

The project uses the following observability stack:

### For Metrics (Required for Grafana dashboards):
- **Prometheus** - Scrapes and stores metrics from the application
- **Actix Web** - Exposes the `/metrics` endpoint on port 9898
- **Grafana** - Visualizes the metrics stored in Prometheus

### For Tracing (Optional):
- **OpenTelemetry** - Sends distributed trace data to an OTLP collector

**Important:** You do NOT need OpenTelemetry to use Grafana for metrics visualization. The metrics are exposed via Prometheus format directly.

## Metrics Collected

### Simulation Success/Failure Counters

The following Prometheus counters track simulation outcomes:

- `simulation_success_total`: Total number of successful simulations
- `simulation_failure_total`: Total number of failed simulations, with a `reason` label containing the revert reason

These metrics are incremented every time a swap simulation completes (successfully or with failure).

#### Revert Reason Labels

Failed simulations include a `reason` label that captures the decoded revert reason from the transaction. This allows you to:
- Track specific error types (e.g., "TychoRouter__NegativeSlippage", "arithmetic underflow or overflow")
- Identify patterns in failures
- Debug issues by grouping failures by their root cause

The revert reason is automatically decoded using the execution simulator's error decoding, which includes:
- Standard Solidity errors (Error(string), Panic(uint256))
- Custom contract errors with full parameter decoding
- Lookups from 4byte.directory for unknown signatures
- Nested error unwrapping for deeply wrapped errors

## Setup

### 1. Prometheus Metrics Endpoint (Required for Grafana)

The application automatically starts a Prometheus metrics server on:
```
http://0.0.0.0:9898/metrics
```

**No configuration is required** - the metrics server starts automatically when the application runs.

This endpoint is what Prometheus scrapes to collect metrics, which are then visualized in Grafana.

### 2. OpenTelemetry Tracing (Optional - for distributed tracing, not metrics)

OpenTelemetry is used for **distributed tracing**, which is separate from the Prometheus metrics used by Grafana.

To enable OpenTelemetry tracing, set the following environment variable:

```bash
export OTLP_EXPORTER_ENDPOINT=http://your-otel-collector:4317
```

If this variable is not set, the application will use standard console logging.

**Note:** OpenTelemetry is NOT required for Grafana dashboards. The metrics flow is:
```
Application → Prometheus (scrapes :9898/metrics) → Grafana (queries Prometheus)
```

OpenTelemetry tracing is an additional observability feature for request tracing.

## Usage

### Running the Application

```bash
cargo run -- --chain ethereum --rpc-url $RPC_URL --tycho-api-key $TYCHO_API_KEY
```

### Viewing Metrics

While the application is running, you can view metrics at:

```bash
curl http://localhost:9898/metrics
```

Example output:
```
# HELP simulation_failure_total Total number of failed simulations with revert reason as label
# TYPE simulation_failure_total counter
simulation_failure_total{reason="TychoRouter__NegativeSlippage(1000000000000000000, 990000000000000000)"} 3
simulation_failure_total{reason="arithmetic underflow or overflow"} 2

# HELP simulation_success_total Total number of successful simulations
# TYPE simulation_success_total counter
simulation_success_total 142
```

## Quick Start Guide

### Step 1: Run the Application
```bash
cargo run -- --chain ethereum --rpc-url $RPC_URL --tycho-api-key $TYCHO_API_KEY
```

The metrics endpoint will automatically start on http://localhost:9898/metrics

### Step 2: Set Up Prometheus

Install Prometheus and add this configuration to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'tycho-integration-test'
    static_configs:
      - targets: ['localhost:9898']
    scrape_interval: 15s
```

Then start Prometheus:
```bash
prometheus --config.file=prometheus.yml
```

Prometheus UI will be available at http://localhost:9090

### Step 3: Set Up Grafana

1. Install and start Grafana
2. Access Grafana at http://localhost:3000 (default credentials: admin/admin)
3. Add Prometheus as a data source:
   - Go to Configuration → Data Sources → Add data source
   - Select "Prometheus"
   - URL: `http://localhost:9090`
   - Click "Save & Test"
4. Create a new dashboard and add panels using the queries from the "Example Prometheus Queries" section below

That's it! No OpenTelemetry setup required for metrics visualization.

### Example Prometheus Queries

**Success rate calculation:**
```promql
rate(simulation_success_total[5m]) / (rate(simulation_success_total[5m]) + sum(rate(simulation_failure_total[5m])))
```

**Total simulations per minute:**
```promql
rate(simulation_success_total[1m]) + sum(rate(simulation_failure_total[1m]))
```

**Failure count over time:**
```promql
sum(increase(simulation_failure_total[1h]))
```

**Failures grouped by revert reason:**
```promql
sum by (reason) (simulation_failure_total)
```

**Top 5 most common revert reasons:**
```promql
topk(5, sum by (reason) (increase(simulation_failure_total[1h])))
```

**Rate of a specific revert reason:**
```promql
rate(simulation_failure_total{reason=~".*NegativeSlippage.*"}[5m])
```

### Suggested Grafana Dashboard Panels

1. **Success Rate (Gauge)**
   - Query: Success rate calculation from above
   - Visualization: Gauge or Stat panel

2. **Simulations Over Time (Graph)**
   - Query: Total simulations per minute
   - Visualization: Time series graph

3. **Success vs Failure (Pie Chart)**
   - Queries:
     - `simulation_success_total`
     - `sum(simulation_failure_total)`
   - Visualization: Pie chart

4. **Top Failure Reasons (Bar Chart)**
   - Query: `topk(10, sum by (reason) (increase(simulation_failure_total[1h])))`
   - Visualization: Bar chart or table

5. **Failure Reasons Over Time (Graph)**
   - Query: `sum by (reason) (rate(simulation_failure_total[5m]))`
   - Visualization: Time series graph with legend

6. **Specific Error Tracking (Table)**
   - Query: `sum by (reason) (simulation_failure_total)`
   - Visualization: Table showing all unique revert reasons and their counts

## Architecture

### Component Flow

```
Simulation Loop
    ↓
metrics::record_simulation_success() / record_simulation_failure()
    ↓
Prometheus Metrics Registry
    ↓
HTTP Server (Actix Web) on :9898/metrics
    ↓
Prometheus Scraper
    ↓
Grafana Dashboard
```

### Code Structure

- `src/metrics.rs`: Metrics initialization and Prometheus server
- `src/ot.rs`: OpenTelemetry tracing configuration
- `src/main.rs`: Integration of metrics into the simulation loop

## Troubleshooting

### Metrics endpoint not accessible

Check that port 9898 is not blocked by a firewall:
```bash
netstat -an | grep 9898
```

### No metrics appearing in Prometheus

1. Verify the application is running
2. Check Prometheus configuration
3. Verify the target is "UP" in Prometheus UI: http://localhost:9090/targets

### OpenTelemetry errors

If you see errors related to OpenTelemetry:
1. Verify `OTLP_EXPORTER_ENDPOINT` is set correctly
2. Check that your OTLP collector is running and accessible
3. Remove the environment variable to fall back to console logging
