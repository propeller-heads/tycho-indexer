def decode_tycho_exchange(exchange: str) -> (str, bool):
    # removes vm prefix if present, returns True if vm prefix was present (vm protocol) or False if native protocol
    return (exchange.split(":")[1], False) if "vm:" in exchange else (exchange, True)
