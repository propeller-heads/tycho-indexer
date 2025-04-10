-- Define the types of entry point (currently only rpc_tracer)
CREATE TYPE entry_point_type AS ENUM (
    'rpc_tracer'
);

CREATE TABLE IF NOT EXISTS "entry_point"(
    "id" bigserial PRIMARY KEY,
    "type" entry_point_type NOT NULL,
    "data" JSONB NOT NULL, -- TODO: should we validate the data with the db check?
    "waiting_for_protocol" bigint REFERENCES "protocol_system"(id),
    UNIQUE (id)
);

CREATE TYPE storage_slot AS (
    address bytea,
    store_key bytea
);

CREATE TABLE IF NOT EXISTS "traced_entry_point"(
    "entry_point_id" bigserial PRIMARY KEY REFERENCES "entry_point"(id),
    "detection_block" bigint REFERENCES "block"(id),
    "retriggers" storage_slot[],
    "accessed_contract" bytea[]
);