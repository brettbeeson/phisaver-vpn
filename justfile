default:
    @just --list

sso:
    aws sso login --profile phisaver

launch *args:
    uv run python cli.py aws launch {{ args }}

status:
    uv run python cli.py aws status
