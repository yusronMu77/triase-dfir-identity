"""Jam yang dapat digeser di uji (sesi, throttle, dan kedaluwarsa bergantung waktu)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class Clock:
    def __init__(self) -> None:
        self._offset = timedelta()

    def now(self) -> datetime:
        return datetime.now(UTC) + self._offset

    def advance(self, delta: timedelta) -> None:
        """Hanya untuk uji: majukan waktu layanan."""
        self._offset += delta
