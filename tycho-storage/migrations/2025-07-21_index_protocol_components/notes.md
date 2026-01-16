# Database Query Optimizations

## 1. EntryPoint Query Optimization

- **Purpose**: Speed up lookup queries on `(protocol_system_id, external_id)` for EntryPoint resolution.
- **Initial Execution Time**: 130ms
- **Optimized Execution Time**: 0.1ms

**Index Added:**

```sql
CREATE INDEX IF NOT EXISTS idx_protocol_system_id_external_id ON protocol_component (protocol_system_id, external_id);
```

## 1. ProtocolComponent count Query Optimization

- **Purpose**: Improve efficiency of count queries (e.g., for pagination) by filtering on protocol_system_id.
- **Initial Execution Time**: 100ms
- **Optimized Execution Time**: 50ms

**Index Added:**

```sql
CREATE INDEX idx_protocol_component_system_id ON protocol_component (protocol_system_id);
```
