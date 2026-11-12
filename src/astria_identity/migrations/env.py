"""Lingkungan Alembic identity. Dipanggil dari `astria_identity.migrate`, bukan dari `alembic.ini`.

Koneksi dan skema datang dari `config.attributes`, sehingga migrasi berjalan di transaksi yang dibuka
pemanggil (PostgreSQL async lewat `run_sync`, atau SQLite).
"""

from alembic import context

from astria_identity.migrate import TARGET_METADATA

if context.is_offline_mode():
    raise RuntimeError("mode offline tidak didukung; jalankan lewat `astria-identity migrate`")

connection = context.config.attributes["connection"]
schema = context.config.attributes.get("schema")

context.configure(
    connection=connection,
    target_metadata=TARGET_METADATA,
    version_table_schema=schema,
    render_as_batch=connection.dialect.name == "sqlite",
)

with context.begin_transaction():
    context.run_migrations()
