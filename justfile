default:
    @just --list
    uv run python cli.py --help

vpn *args:
    uv run python cli.py {{args}}

sso:
    aws sso login --profile phisaver
