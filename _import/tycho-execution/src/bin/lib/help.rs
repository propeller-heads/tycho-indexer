pub const HELP_TEXT: &str = "\
USAGE:
    tycho-encode [ROUTER_ADDRESS] [PRIVATE_KEY]

ARGS:
    ROUTER_ADDRESS    The address of the router contract [default: 0x1234567890123456789012345678901234567890]
    PRIVATE_KEY      The private key for signing Permit2 approvals (required when direct_execution is false)

The program reads a JSON object from stdin containing the swap details and outputs the encoded transaction.
The JSON object should have the following structure:
{
    \"sender\": \"0x...\",
    \"receiver\": \"0x...\",
    \"given_token\": \"0x...\",
    \"given_amount\": \"123...\",
    \"checked_token\": \"0x...\",
    \"exact_out\": false,
    \"slippage\": 0.01,
    \"expected_amount\": \"123...\",
    \"check_amount\": \"123...\",
    \"swaps\": [{
        \"component\": {
            \"id\": \"...\",
            \"protocol_system\": \"...\",
            \"protocol_type_name\": \"...\",
            \"chain\": \"ethereum\",
            \"tokens\": [\"0x...\"],
            \"contract_ids\": [\"0x...\"],
            \"static_attributes\": {\"key\": \"0x...\"}
        },
        \"token_in\": \"0x...\",
        \"token_out\": \"0x...\",
        \"split\": 1.0
    }],
    \"router_address\": \"0x...\",
    \"direct_execution\": false
}";
