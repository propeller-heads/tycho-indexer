-- dropping tables will drop any triggers or indices along with it
DROP TABLE audit_log;

DROP TABLE protocol_calls_contract;

DROP TABLE contract_storage;

DROP TABLE contract_code;

DROP TABLE account_balance;

DROP TABLE protocol_holds_token;

DROP TABLE "token";

DROP TABLE "account";

DROP TABLE protocol_state;

DROP TABLE protocol_component;

DROP TABLE extraction_state;

DROP TABLE protocol_type;

DROP TABLE protocol_system;

DROP TABLE "transaction";

DROP TABLE "block";

DROP TABLE chain;

-- custom types
DROP TYPE financial_protocol_type;

DROP TYPE protocol_implementation_type;

-- extensions
DROP EXTENSION hstore;

DROP EXTENSION pg_trgm;

-- drop trigger functions
DROP FUNCTION audit_trigger;

DROP FUNCTION update_modified_column;

DROP FUNCTION invalidate_previous_entry_protocol_calls_contract;

DROP FUNCTION invalidate_previous_entry_protocol_state;

DROP FUNCTION invalidate_previous_entry_account_balance;

DROP FUNCTION invalidate_previous_entry_contract_code;
