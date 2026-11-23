"""Select durable SQLite journaling for local or network-backed state volumes."""
import os
def configure(connection):
    mode=os.environ.get('SQLITE_JOURNAL_MODE','WAL').upper()
    if mode not in ('WAL','DELETE'):raise RuntimeError('SQLITE_JOURNAL_MODE must be WAL or DELETE.')
    actual=connection.execute('PRAGMA journal_mode='+mode).fetchone()[0].upper()
    if actual!=mode:raise RuntimeError('The requested database journal mode could not be enabled.')
