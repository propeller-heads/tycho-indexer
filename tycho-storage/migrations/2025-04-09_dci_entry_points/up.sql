-- Define the types of entry point tracing (currently only rpc_tracer)
CREATE TYPE entry_point_tracing_type AS ENUM (
    'rpc_tracer'
);

CREATE TABLE IF NOT EXISTS "entry_point"(
    "id" bigserial PRIMARY KEY,
    "target" bytea NOT NULL,
    "signature" text NOT NULL,
    UNIQUE ("target", "signature")
);

CREATE TABLE IF NOT EXISTS "entry_point_tracing_data"(
    "entry_point_id" bigint REFERENCES "entry_point"(id) NOT NULL,
    "tracing_type" entry_point_tracing_type NOT NULL,
    "data" JSONB,
    PRIMARY KEY ("entry_point_id", "tracing_type", "data")
);

CREATE TABLE IF NOT EXISTS "protocol_component_holds_entry_point"(
    "protocol_component_id" bigint REFERENCES "protocol_component"(id) NOT NULL,
    "entry_point_id" bigint REFERENCES "entry_point"(id) NOT NULL,
    PRIMARY KEY ("protocol_component_id", "entry_point_id")
);

CREATE TABLE IF NOT EXISTS "traced_entry_point"(
    "entry_point_id" bigint NOT NULL REFERENCES "entry_point"(id) PRIMARY KEY,
    "detection_block" bigint NOT NULL REFERENCES "block"(id),
    "detection_data" JSONB NOT NULL
);

-- Keep tracks of the m2m relation between entry_points and accounts
CREATE TABLE IF NOT EXISTS "entry_point_calls_account"(
    "entry_point_id" bigint NOT NULL REFERENCES "entry_point"(id),
    "account_id" bigint NOT NULL REFERENCES "account"(id),
    PRIMARY KEY("entry_point_id","account_id")
)