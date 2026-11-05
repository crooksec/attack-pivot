"""``afp settings``: options and encrypted secrets."""

import getpass
import sys

from attack_pivot.db import connect
from attack_pivot.settings import options, secrets
from attack_pivot.settings.redact import install_log_filter


def register(subparsers):
    parser = subparsers.add_parser("settings", help="Options and stored secrets")
    sub = parser.add_subparsers(
        dest="settings_command", required=True, metavar="<action>"
    )

    show = sub.add_parser("show", help="Options and where each secret comes from")
    show.set_defaults(command=_show)

    set_ = sub.add_parser("set", help="Set an option")
    set_.add_argument("key", choices=sorted(options.OPTIONS))
    set_.add_argument("value")
    set_.set_defaults(command=_set)

    reset = sub.add_parser("reset", help="Return an option to its default")
    reset.add_argument("key", choices=sorted(options.OPTIONS))
    reset.set_defaults(command=_reset)

    secret = sub.add_parser(
        "secret", help="Store or remove a secret (the value is never printed)"
    )
    secret_sub = secret.add_subparsers(
        dest="secret_command", required=True, metavar="<action>"
    )
    put = secret_sub.add_parser(
        "set", help="Read the value from stdin or a prompt, not the command line"
    )
    put.add_argument("name", choices=sorted(secrets.KNOWN))
    put.set_defaults(command=_secret_set)
    rm = secret_sub.add_parser("delete", help="Remove a stored secret")
    rm.add_argument("name", choices=sorted(secrets.KNOWN))
    rm.set_defaults(command=_secret_delete)


def _show(args):
    with connect(args.database_url) as conn:
        for o in options.list_all(conn):
            mark = "" if o["is_default"] else "  (set)"
            print(f"{o['key']:<26} {o['value']}{mark}")
        print()
        for s in secrets.status(conn):
            note = (
                "  (stored value unreadable with the current master key)"
                if s["unreadable"]
                else ""
            )
            print(f"{s['name']:<18} {s['source']}{note}")


def _set(args):
    with connect(args.database_url) as conn:
        value = options.set_value(conn, args.key, args.value)
    print(f"{args.key} = {value}")


def _reset(args):
    with connect(args.database_url) as conn:
        options.reset(conn, args.key)
    print(f"{args.key} reset to default")


def _secret_set(args):
    install_log_filter()
    value = (
        sys.stdin.readline()
        if not sys.stdin.isatty()
        else getpass.getpass(f"{args.name}: ")
    )
    with connect(args.database_url) as conn:
        try:
            secrets.set_secret(conn, args.name, value)
        except ValueError as e:
            raise RuntimeError(str(e)) from None
    print(f"stored {args.name}")


def _secret_delete(args):
    with connect(args.database_url) as conn:
        removed = secrets.delete_secret(conn, args.name)
    print(f"removed {args.name}" if removed else f"{args.name} was not stored")
