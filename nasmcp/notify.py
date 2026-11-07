"""Phone notifications: Home Assistant notify service or a generic webhook."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .config import Settings

log = logging.getLogger("nasmcp.notify")


class NotifyError(Exception):
    pass


def ha_panel(settings: Settings, title: str, message: str, notification_id: str) -> None:
    """Also show the request in Home Assistant's notification panel (bell icon),
    so it can be answered from a computer. Best effort."""
    if settings.notify_mode != "ha" or not (settings.ha_url and settings.ha_token):
        return
    try:
        httpx.post(f"{settings.ha_url.rstrip('/')}/api/services/persistent_notification/create",
                   json={"title": title, "message": message, "notification_id": notification_id},
                   headers={"Authorization": f"Bearer {settings.ha_token}"}, timeout=15)
    except httpx.HTTPError as e:
        log.warning("HA panel notification failed: %s", e)


def ha_panel_dismiss(settings: Settings, notification_id: str) -> None:
    if settings.notify_mode != "ha" or not (settings.ha_url and settings.ha_token):
        return
    try:
        httpx.post(f"{settings.ha_url.rstrip('/')}/api/services/persistent_notification/dismiss",
                   json={"notification_id": notification_id},
                   headers={"Authorization": f"Bearer {settings.ha_token}"}, timeout=15)
    except httpx.HTTPError:
        pass


def send(settings: Settings, title: str, message: str,
         actions: list[dict[str, str]] | None = None, tag: str | None = None) -> None:
    """actions: [{"title": "Approve", "uri": "https://..."}] (opened on tap)."""
    mode = settings.notify_mode
    if mode == "ha":
        if not (settings.ha_url and settings.ha_token and settings.ha_notify_service):
            raise NotifyError("Home Assistant notify is not configured")
        domain, _, service = settings.ha_notify_service.partition(".")
        data: dict[str, Any] = {"title": title, "message": message}
        extra: dict[str, Any] = {"priority": "high", "ttl": 0}
        if tag:
            extra["tag"] = tag
        if actions:
            extra["actions"] = [{"action": "URI", "title": a["title"], "uri": a["uri"]}
                                for a in actions]
        data["data"] = extra
        url = f"{settings.ha_url.rstrip('/')}/api/services/{domain}/{service}"
        try:
            r = httpx.post(url, json=data, timeout=15,
                           headers={"Authorization": f"Bearer {settings.ha_token}"})
        except httpx.HTTPError as e:
            raise NotifyError(f"cannot reach Home Assistant: {e}") from e
        if r.status_code >= 400:
            raise NotifyError(f"Home Assistant replied {r.status_code}")
    elif mode == "webhook":
        if not settings.webhook_url:
            raise NotifyError("webhook_url is not configured")
        try:
            r = httpx.post(settings.webhook_url, timeout=15,
                           json={"title": title, "message": message, "actions": actions or []})
        except httpx.HTTPError as e:
            raise NotifyError(f"webhook failed: {e}") from e
        if r.status_code >= 400:
            raise NotifyError(f"webhook replied {r.status_code}")
    else:
        raise NotifyError("notifications are off (notify_mode: none)")
