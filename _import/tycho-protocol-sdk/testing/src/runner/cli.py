import argparse
from runner import TestRunner


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run indexer within a specified range of blocks"
    )
    parser.add_argument("--package", type=str, help="Name of the package to test.")
    parser.add_argument(
        "--tycho-logs", action="store_true", help="Enable Tycho logs."
    )
    parser.add_argument(
        "--db-url",
        default="postgres://postgres:mypassword@localhost:5431/tycho_indexer_0",
        type=str,
        help="Postgres database URL for the Tycho indexer. Default: postgres://postgres:mypassword@localhost:5431/tycho_indexer_0",
    )
    parser.add_argument(
        "--vm-traces", action="store_true", help="Enable tracing during vm simulations."
    )
    args = parser.parse_args()

    test_runner = TestRunner(
        args.package, args.tycho_logs, db_url=args.db_url, vm_traces=args.vm_traces
    )
    test_runner.run_tests()


if __name__ == "__main__":
    main()
