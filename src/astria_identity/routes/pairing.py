"""Kode pairing kanal: terbit (pengguna login) dan klaim (diteruskan api dari Gateway)."""

from __future__ import annotations

from astria_contracts.openapi.identity_internal import (
    PairingClaim,
    PairingClaimResult,
    PairingCode,
    PairingCodeRequest,
)
from fastapi import APIRouter

from astria_identity import pairing
from astria_identity.routes.deps import Ident, Principal

router = APIRouter(prefix="/internal/v1", tags=["pairing"])


@router.post("/pairing-codes", response_model=PairingCode, status_code=201)
async def issue_code(ident: Ident, principal: Principal, body: PairingCodeRequest | None = None) -> PairingCode:
    issued = await pairing.issue(ident, principal, body.channel if body else None)
    return PairingCode.model_validate(issued)


@router.post("/pairing/claim", response_model=PairingClaimResult)
async def claim_code(body: PairingClaim, ident: Ident, _caller: Principal) -> PairingClaimResult:
    claimed = await pairing.claim(ident, channel=body.channel, external_id_hash=body.external_id_hash, code=body.code)
    return PairingClaimResult.model_validate(claimed)
