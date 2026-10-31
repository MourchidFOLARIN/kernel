"""Livraison d'un message (REST ou WS) avec flux Ève et interception éventuelle."""
from app import config
from app.ws.hub import eve, eve_feed, hub


def eve_raw(payload: dict, sender: str) -> dict:
    from app.models import now_utc
    return {
        "type": "eve.raw",
        "at": now_utc().isoformat() + "Z",
        "sender": sender,
        "frame": {
            "conversation_id": payload.get("conversation_id"),
            "sender_id": payload.get("sender_id"),
            "algo": payload.get("algo"), "mode": payload.get("mode"),
            "iv": payload.get("iv"), "ciphertext": payload.get("ciphertext"),
            "tag": payload.get("tag"), "key_dist": payload.get("key_dist"),
            "key_fp": payload.get("key_fp"),
        },
    }


async def deliver_to_recipients(payload: dict, sender_username: str, recipients: list[int]) -> dict:
    """Diffuse au flux Ève, puis relaye ou retient selon le mode interception.

    Retourne {"held": hold_id|None}.
    """
    await eve_feed(hub, eve_raw(payload, sender=sender_username))
    if config.DEMO_MODE and eve.intercept and recipients:
        hid = eve.next_hold_id()
        eve.held[hid] = {"payload": payload, "recipients": list(recipients),
                         "sender": sender_username}
        await eve_feed(hub, {"type": "eve.held", "hold_id": hid,
                             "sender": sender_username, "message": payload})
        return {"held": hid}
    await hub.send_to_users(recipients, payload)
    return {"held": None}
