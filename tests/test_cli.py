from bugbounty.cli import build_parser


def test_cli_parser_supports_core_commands():
    parser = build_parser()
    args = parser.parse_args(["init", "--workspace", ".tmp"])

    assert args.command == "init"
    assert args.workspace == ".tmp"

    args = parser.parse_args(["status", "--workspace", ".tmp"])
    assert args.command == "status"
