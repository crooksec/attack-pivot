"""
Typed options stored in ``pivot.setting``. An option with no stored value takes its default.

Each option is described once here; the CLI, the API and the Explorer's Settings page all read the
same description, so a new option needs one entry.
"""

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Option:
    key: str
    label: str
    help: str
    kind: str  # "choice" | "int"
    default: object
    choices: tuple = ()
    minimum: int | None = None
    maximum: int | None = None
    group: str = "Search"

    def validate(self, value):
        if self.kind == "choice":
            if value not in self.choices:
                raise ValueError(f"{self.key}: choose one of {', '.join(self.choices)}")
            return value
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"{self.key}: expected a whole number")
        try:
            number = int(value)
        except ValueError:
            raise ValueError(f"{self.key}: expected a whole number") from None
        if self.minimum is not None and number < self.minimum:
            raise ValueError(f"{self.key}: at least {self.minimum}")
        if self.maximum is not None and number > self.maximum:
            raise ValueError(f"{self.key}: at most {self.maximum}")
        return number

    def describe(self):
        return {
            "key": self.key,
            "label": self.label,
            "help": self.help,
            "kind": self.kind,
            "default": self.default,
            "choices": list(self.choices),
            "minimum": self.minimum,
            "maximum": self.maximum,
            "group": self.group,
        }


OPTIONS = {
    o.key: o
    for o in (
        Option(
            "search.provider",
            "Search provider",
            "Which search API `afp search` calls. 'both' queries Serper and Brave and merges the results.",
            "choice",
            "off",
            ("off", "serper", "brave", "both"),
        ),
        Option(
            "search.results_per_query",
            "Results per query",
            "How many results to ask each provider for.",
            "int",
            10,
            minimum=1,
            maximum=20,
        ),
        Option(
            "search.freshness",
            "Freshness",
            "Only results published within this window.",
            "choice",
            "any",
            ("any", "day", "week", "month", "year"),
        ),
        Option(
            "search.budget.serper",
            "Serper monthly budget",
            "Queries per calendar month (UTC). 0 blocks Serper.",
            "int",
            100,
            minimum=0,
            maximum=1_000_000,
        ),
        Option(
            "search.budget.brave",
            "Brave monthly budget",
            "Queries per calendar month (UTC). 0 blocks Brave.",
            "int",
            100,
            minimum=0,
            maximum=1_000_000,
        ),
    )
}


def get(conn, key):
    option = OPTIONS[key]
    row = conn.execute(
        "SELECT value FROM pivot.setting WHERE key = %s", (key,)
    ).fetchone()
    if row is None:
        return option.default
    try:
        return option.validate(row["value"])
    except ValueError:
        return option.default


def set_value(conn, key, value):
    if key not in OPTIONS:
        raise ValueError(f"unknown setting {key!r}")
    value = OPTIONS[key].validate(value)
    conn.execute(
        "INSERT INTO pivot.setting (key, value) VALUES (%s, %s::jsonb) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        (key, json.dumps(value)),
    )
    conn.commit()
    return value


def reset(conn, key):
    if key not in OPTIONS:
        raise ValueError(f"unknown setting {key!r}")
    conn.execute("DELETE FROM pivot.setting WHERE key = %s", (key,))
    conn.commit()


def list_all(conn):
    """Every option's description with its current ``value`` and whether it is the default."""
    stored = {r["key"] for r in conn.execute("SELECT key FROM pivot.setting")}
    out = []
    for option in OPTIONS.values():
        out.append(
            {
                **option.describe(),
                "value": get(conn, option.key),
                "is_default": option.key not in stored,
            }
        )
    return out
