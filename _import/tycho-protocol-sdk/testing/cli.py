import argparse
from runner import TestRunner


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run indexer within a specified range of blocks"
    )
    parser.add_argument(
        "--test_yaml_path", type=str, help="Path to the test configuration YAML file."
    )
    parser.add_argument(
        "--with_binary_logs",
        action="store_true",
        help="Flag to activate logs from Tycho.",
    )
    args = parser.parse_args()

    test_runner = TestRunner(args.test_yaml_path, args.with_binary_logs)
    test_runner.run_tests()


if __name__ == "__main__":
    main()
