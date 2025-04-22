-- Define the types of entry point tracing (currently only rpc_tracer)
CREATE TYPE entry_point_tracing_type AS ENUM (
    'rpc_tracer'
);

CREATE TABLE IF NOT EXISTS "entry_point"(
    "id" bigserial PRIMARY KEY,
    "external_id" text UNIQUE NOT NULL,
    "target" bytea NOT NULL,
    "signature" text NOT NULL,
    "created_at" timestamp with time zone NOT NULL DEFAULT now(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE ("target", "signature")
);

CREATE TABLE IF NOT EXISTS "entry_point_tracing_data"(
    "id" bigserial PRIMARY KEY,
    "entry_point_id" bigint REFERENCES "entry_point"(id) ON DELETE CASCADE NOT NULL,
    "tracing_type" entry_point_tracing_type NOT NULL,
    "data" JSONB,
    "created_at" timestamp with time zone NOT NULL DEFAULT now(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
    UNIQUE ("entry_point_id", "tracing_type", "data")
);

CREATE TABLE IF NOT EXISTS "protocol_component_holds_entry_point_tracing_data"(
    "protocol_component_id" bigint REFERENCES "protocol_component"(id) ON DELETE CASCADE NOT NULL,
    "entry_point_tracing_data_id" bigint REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE NOT NULL,
    PRIMARY KEY ("protocol_component_id", "entry_point_tracing_data_id")
);

CREATE TABLE IF NOT EXISTS "entry_point_tracing_result"(
    "entry_point_tracing_data_id" bigint NOT NULL REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE PRIMARY KEY,
    "detection_block" bigint NOT NULL REFERENCES "block"(id),
    "detection_data" JSONB NOT NULL,
    "created_at" timestamp with time zone NOT NULL DEFAULT now(),
    "updated_at" timestamp with time zone NOT NULL DEFAULT now()
);

-- Keep tracks of the m2m relation between entry_points and accounts
CREATE TABLE IF NOT EXISTS "entry_point_tracing_data_calls_account"(
    "entry_point_tracing_data_id" bigint NOT NULL REFERENCES "entry_point_tracing_data"(id) ON DELETE CASCADE,
    "account_id" bigint NOT NULL REFERENCES "account"(id) ON DELETE CASCADE,
    PRIMARY KEY("entry_point_tracing_data_id","account_id")
)