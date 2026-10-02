from __future__ import annotations

from honeybot.reconstruct import reconstruct


async def finalize_session(app, session_id: str, bytes_in: int, bytes_out: int, banner: str) -> None:
    bundle = await app.store.bundle(session_id)
    if not bundle.get("session"):
        return
    result = reconstruct(bundle)
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
