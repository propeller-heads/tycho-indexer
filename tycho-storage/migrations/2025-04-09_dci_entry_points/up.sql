-- Define the types of entry point tracing (currently only rpc_tracer)
CREATE TYPE entry_point_tracing_type AS ENUM (
    'rpc_tracer'
);

CREATE TABLE IF NOT EXISTS "entry_point"(
    "id" bigserial PRIMARY KEY,
    "external_id" text UNIQUE NOT NULL,
    "target" bytea NOT NULL,
    "signature" text NOT NULL,
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("target", "signature")
);

CREATE TABLE IF NOT EXISTS "entry_point_tracing_data"(
    "id" bigserial PRIMARY KEY,
    "entry_point_id" bigint REFERENCES "entry_point"(id) ON DELETE CASCADE NOT NULL,
    "tracing_type" entry_point_tracing_type NOT NULL,
    "data" JSONB,
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("entry_point_id", "tracing_type", "data")
);

CREATE TABLE IF NOT EXISTS "protocol_component_holds_entry_point_tracing_data"(
    "protocol_component_id" bigint REFERENCES "protocol_component"(id) ON DELETE CASCADE NOT NULL,
    "entry_point_tracing_data_id" bigint REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE NOT NULL,
    PRIMARY KEY ("protocol_component_id", "entry_point_tracing_data_id")
);

CREATE TABLE IF NOT EXISTS "entry_point_tracing_result"(
    "id" bigserial PRIMARY KEY,
    "entry_point_tracing_data_id" bigint UNIQUE NOT NULL REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE, -- Currently only one result per entry point tracing data, if we want to allow multiple results per entry point tracing data (like for versioning), we need to remove the UNIQUE constraint
    "detection_block" bigint NOT NULL REFERENCES "block"(id),
    "detection_data" JSONB NOT NULL,
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Keep tracks of the m2m relation between entry_points and accounts
CREATE TABLE IF NOT EXISTS "entry_point_tracing_data_calls_account"(
    "entry_point_tracing_data_id" bigint NOT NULL REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE,
    "account_id" bigint NOT NULL REFERENCES "account"(id) ON DELETE CASCADE,
    PRIMARY KEY("entry_point_tracing_data_id","account_id")
);

CREATE TRIGGER update_modtime_entry_point
    BEFORE UPDATE ON "entry_point"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_entry_point_tracing_data
    BEFORE UPDATE ON "entry_point_tracing_data"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_entry_point_tracing_result
    BEFORE UPDATE ON "entry_point_tracing_result"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();