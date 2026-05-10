from src.parsing.log_parser import LogParser


def test_parser_extracts_template_and_parameters() -> None:
    parser = LogParser()
    template, parameters = parser.parse("User 123 logged in from 192.168.1.10")

    assert "<*>" in template
    assert parameters
