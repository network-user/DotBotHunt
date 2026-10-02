from __future__ import annotations

import logging

from honeybot.reconstruct import reconstruct

log = logging.getLogger("honeybot")

# Эти метки сами по себе повод смотреть сессию, даже если оператор не открыл панель.
_ALERT = {"fetch_and_run", "miner", "reverse_shell"}


async def finalize_session(app, session_id: str, bytes_in: int, bytes_out: int, banner: str) -> None:
    bundle = await app.store.bundle(session_id)
    if not bundle.get("session"):
        return
    result = reconstruct(bundle)
    hit = _ALERT.intersection(result.tags)
    if hit:
        log.warning(
            "сессия %s с %s: %s",
            session_id,
            bundle["session"].get("ip") or "",
            ",".join(sorted(hit)),
        )
    await app.store.finish(
        session_id,
        primary=result.primary,
        summary=result.summary,
        command_tags=result.command_tags,
        http_tags=result.http_tags,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        banner=banner,
    )
