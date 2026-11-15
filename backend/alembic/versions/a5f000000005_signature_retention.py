"""Retain signature evidence and remove cascading signature/session foreign keys.

Additive revision; copies all existing rows using Alembic batch operations.
"""
from alembic import op

revision = "a5f000000005"
down_revision = "a4f000000004"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("This retention migration targets SQLite")
    # pysqlite legacy mode does not BEGIN for DDL. Make table copies + trigger
    # replacement transactional and serialize against application writers.
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
        raise RuntimeError("Existing foreign-key violations; repair before migration")
    counts = {table: connection.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar_one()
              for table in ("signatures", "signing_sessions")}
    op.execute("DROP TRIGGER IF EXISTS version_immutable")
    convention = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}
    for table, fields in (
        ("signatures", (("version_id", "document_versions"), ("signer_id", "users"), ("key_id", "public_keys"))),
        ("signing_sessions", (("version_id", "document_versions"), ("user_id", "users"), ("key_id", "public_keys"))),
    ):
        with op.batch_alter_table(table, naming_convention=convention, recreate="always") as batch:
            for column, target in fields:
                name = f"fk_{table}_{column}_{target}"
                batch.drop_constraint(name, type_="foreignkey")
                batch.create_foreign_key(name, target, [column], ["id"])
    op.execute("""CREATE TRIGGER version_immutable BEFORE UPDATE ON document_versions
WHEN NEW.id IS NOT OLD.id OR NEW.document_id IS NOT OLD.document_id
 OR NEW.version_no IS NOT OLD.version_no OR NEW.file_sha256 IS NOT OLD.file_sha256
 OR NEW.storage_key IS NOT OLD.storage_key OR NEW.file_size_bytes IS NOT OLD.file_size_bytes
 OR NEW.original_filename IS NOT OLD.original_filename OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.state != NEW.state AND NOT (
     (OLD.state = 'DRAFT' AND NEW.state = 'READY_TO_SIGN')
     OR (OLD.state = 'READY_TO_SIGN' AND NEW.state = 'SIGNED' AND EXISTS (SELECT 1 FROM signatures WHERE version_id = NEW.id))
 ))
 OR (OLD.locked_at IS NOT NULL AND NEW.locked_at IS NOT OLD.locked_at)
BEGIN SELECT RAISE(ABORT, 'Immutable version or invalid transition'); END;""")
    op.execute("""CREATE TRIGGER signature_no_update BEFORE UPDATE ON signatures
BEGIN SELECT RAISE(ABORT, 'Signature evidence is immutable'); END;""")
    op.execute("""CREATE TRIGGER signature_no_delete BEFORE DELETE ON signatures
BEGIN SELECT RAISE(ABORT, 'Signature evidence retention forbids deletion'); END;""")

    for table, expected in counts.items():
        if connection.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar_one() != expected:
            raise RuntimeError("Retention migration row-count mismatch")
    if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
        raise RuntimeError("Retention migration foreign-key violation")


def downgrade():
    raise RuntimeError("Signature evidence retention forbids downgrade")
