import os
import sys
import requests
import psycopg2
from psycopg2 import sql

# Configuration from environment variables
RPC_URL = os.getenv("RPC_URL")
DATABASE_URL = os.getenv("DATABASE_URL")

# The address to update (can be passed as argument or hardcoded)
ADDRESS = (
    sys.argv[1] if len(sys.argv) > 1 else "0xf2f305d14dcd8aaef887e0428b3c9534795d0d60"
)


def get_balance_from_rpc(address):
    """Fetch balance from RPC node using eth_getBalance"""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }

    print(f"Fetching balance for address: {address}")
    response = requests.post(RPC_URL, json=payload)
    response.raise_for_status()

    result = response.json()

    if "error" in result:
        raise Exception(f"RPC Error: {result['error']}")

    # Balance is returned as hex string (e.g., "0x6CCC9BF8C29D9A07")
    balance_hex = result["result"]

    return balance_hex


def update_balance_in_db(address, balance_hex):
    """Update balance in PostgreSQL database"""
    conn = None

    try:
        # Connect to database
        print("Connecting to database...")
        conn = psycopg2.connect(DATABASE_URL)

        cursor = conn.cursor()

        # Remove '0x' prefix and pad to 64 characters
        balance_clean = balance_hex.replace("0x", "").zfill(64)
        address_clean = address.replace("0x", "")

        print(f"Balance (hex): {balance_clean}")
        print(f"Balance (decimal): {int(balance_hex, 16)}")

        # Update query
        query = """
            UPDATE account_balance
            SET balance = %s
            FROM account a
            WHERE account_balance.account_id = a.id
              AND a.address = %s
              AND account_balance.valid_to IS NULL
        """

        cursor.execute(
            query, (bytes.fromhex(balance_clean), bytes.fromhex(address_clean))
        )

        conn.commit()

        print("Balance updated successfully!")

        cursor.close()

    except Exception as e:
        if conn:
            conn.rollback()
        raise e

    finally:
        if conn:
            conn.close()


def main():
    try:
        # Validate environment variables
        if not RPC_URL:
            raise ValueError("RPC_URL environment variable is required")
        if not DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable is required")

        # Fetch balance from RPC
        balance_hex = get_balance_from_rpc(ADDRESS)

        # Update database
        update_balance_in_db(ADDRESS, balance_hex)

        print("\nScript completed successfully")
        return 0

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
