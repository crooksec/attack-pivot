"""``afp db`` commands."""

from attack_pivot.db import connect, migrate as migrations


def register(subparsers):
    parser = subparsers.add_parser(
        "db", help="Initialise and migrate the pivot database"
    )
    sub = parser.add_subparsers(dest="db_command", required=True, metavar="<action>")
    init = sub.add_parser(
        "init", help="Create extension, graph and schema, then migrate"
    )
    init.set_defaults(command=_init)
    migrate = sub.add_parser("migrate", help="Apply pending migrations")
    migrate.set_defaults(command=_migrate)


def _init(args):
    with connect(args.database_url) as conn:
        migrations.init(conn)
        applied = migrations.migrate(conn)
    print(f"initialised; applied: {', '.join(applied) or 'nothing (up to date)'}")


def _migrate(args):
    with connect(args.database_url) as conn:
        applied = migrations.migrate(conn)
    print(f"applied: {', '.join(applied) or 'nothing (up to date)'}")
