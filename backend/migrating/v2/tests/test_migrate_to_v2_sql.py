"""Regression tests for SQL injection prevention in migrate_to_v2.

These tests verify that the information_schema query in
_bump_auto_increment_id uses parameterized queries instead of
f-string interpolation of schema/table names.

No Django or application imports are needed — the tests inspect the
source file directly so they are safe to run in any pytest session.
"""

import ast
import pathlib

MIGRATE_FILE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "management"
    / "commands"
    / "migrate_to_v2.py"
)


def _read_source() -> str:
    return MIGRATE_FILE.read_text(encoding="utf-8")


class TestNoSQLStringLiteralInjection:
    """Verify that schema/table names are not embedded as string
    literals inside SQL via f-strings.
    """

    def test_info_schema_query_uses_parameterized_placeholders(self):
        """The information_schema.columns query must use %s
        placeholders, not f-string '{var}' interpolation.
        """
        source = _read_source()
        assert "table_schema = %s" in source
        assert "table_name = %s" in source

    def test_no_fstring_in_info_schema_query(self):
        """Ensure no f-string injects values into WHERE clauses
        that compare against information_schema columns.
        """
        source = _read_source()
        assert "table_schema = '{" not in source
        assert "table_name = '{" not in source

    def test_bump_method_passes_params_tuple(self):
        """The execute() call for the info_schema query must pass
        a params tuple as the second argument (not inline SQL).
        """
        source = _read_source()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Look for dest_cursor.execute(...) calls
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "execute"
                and isinstance(func.value, ast.Name)
                and func.value.id == "dest_cursor"
            ):
                continue
            # Check if the SQL string contains info_schema
            if not node.args:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(
                first_arg.value, str
            ):
                if "information_schema" in first_arg.value:
                    # Must have a second argument (the params tuple)
                    assert len(node.args) >= 2 or node.keywords, (
                        "info_schema execute() call must include "
                        "a params argument"
                    )
                    return

        raise AssertionError(
            "Could not find dest_cursor.execute() call with "
            "information_schema query"
        )
