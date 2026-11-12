"""Direktori pengguna minimal (subset identity#4, note app-identity bagian 4): pengguna, peran, dan seed dev.

Hanya jalur baca untuk Command Facade api dan seed dev. Login, sesi, kata sandi, dan endpoint admin belum ada.
Kolom `active` menggantikan `status` di note untuk subset ini; peran dibatasi empat nilai tabel 7.1 arsitektur.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, get_args

from astria_common.component import Check
from astria_common.db import Database
from astria_common.log import get_logger
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    MetaData,
    Table,
    Text,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection

log = get_logger(__name__)

USER_ID = r"^usr_[A-Za-z0-9]+$"
Role = Literal["analis", "dfir", "pimpinan", "admin"]
ROLES: tuple[str, ...] = get_args(Role)

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Text, primary_key=True),
    Column("username", Text, nullable=False),
    Column("display_name", Text, nullable=False),
    Column("active", Boolean, nullable=False, server_default="true"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
Index("users_username_lower", func.lower(users.c.username), unique=True)
user_roles = Table(
    "user_roles",
    metadata,
    Column("user_id", Text, ForeignKey("users.user_id"), primary_key=True),
    Column("role", Text, primary_key=True),
    CheckConstraint(f"role IN ({', '.join(repr(r) for r in ROLES)})", name="user_roles_role"),
)


class User(BaseModel):
    """Bentuk `GET /internal/v1/users/{user_id}` dan satu entri seed."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(pattern=USER_ID, max_length=64)
    username: str = Field(min_length=1, max_length=100)
    display_name: str = Field(min_length=1, max_length=200)
    roles: list[Role] = Field(default_factory=list)
    active: bool = True


class Seed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[User] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> Seed:
        ids = [u.user_id for u in self.users]
        names = [u.username.lower() for u in self.users]
        if len(set(ids)) != len(ids) or len(set(names)) != len(names):
            raise ValueError("user_id atau username ganda di berkas seed")
        return self


def load_seed(path: Path) -> Seed:
    """Baca dan validasi berkas seed saat rakit aplikasi: berkas rusak menghentikan start, bukan diam-diam."""
    return Seed.model_validate_json(path.read_bytes())


_USER_COLUMNS = [users.c[n] for n in User.model_fields if n != "roles"]


async def get_user(conn: AsyncConnection, user_id: str) -> User | None:
    """Satu kueri: pengguna LEFT JOIN peran (tanpa baris = tidak ada)."""
    query = (
        select(*_USER_COLUMNS, user_roles.c.role)
        .select_from(users.outerjoin(user_roles))
        .where(users.c.user_id == user_id)
        .order_by(user_roles.c.role)
    )
    rows = (await conn.execute(query)).mappings().all()
    if not rows:
        return None
    fields = {c.name: rows[0][c.name] for c in _USER_COLUMNS}
    return User(**fields, roles=[r["role"] for r in rows if r["role"] is not None])


async def apply_seed(conn: AsyncConnection, seed: Seed) -> None:
    """Idempoten: pengguna seed dibuat atau disamakan, perannya diganti persis seperti di berkas."""
    for user in seed.users:
        values: dict[str, Any] = {"username": user.username, "display_name": user.display_name, "active": user.active}
        exists = await conn.scalar(select(users.c.user_id).where(users.c.user_id == user.user_id))
        if exists is None:
            await conn.execute(insert(users).values(user_id=user.user_id, **values))
        else:
            await conn.execute(
                update(users).where(users.c.user_id == user.user_id).values(**values, updated_at=func.now())
            )
        await conn.execute(delete(user_roles).where(user_roles.c.user_id == user.user_id))
        if user.roles:
            await conn.execute(insert(user_roles), [{"user_id": user.user_id, "role": r} for r in set(user.roles)])


@dataclass
class Seeder:
    """Komponen: terapkan seed dev sekali setelah basis data siap. /ready `down` sampai selesai."""

    db: Database
    seed: Seed
    name: str = "seed"
    required: bool = True
    done: bool = False
    error: str | None = None
    _task: asyncio.Task[None] | None = field(default=None, repr=False)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="identity-seed")

    async def _run(self) -> None:
        await self.db.wait_ready()
        try:
            async with self.db.engine.begin() as conn:
                await apply_seed(conn, self.seed)
        except Exception as exc:  # noqa: BLE001 - terlihat di /ready; seed tidak boleh menjatuhkan proses
            self.error = type(exc).__name__
            log.error("seed_gagal", error=self.error)
            return
        self.done = True
        log.info("seed_diterapkan", users=len(self.seed.users))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        if self.done:
            return Check("ok", f"users={len(self.seed.users)}")
        return Check("down", f"seed belum diterapkan ({self.error or 'menunggu basis data'})")
