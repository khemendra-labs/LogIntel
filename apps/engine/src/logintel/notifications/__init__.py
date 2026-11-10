"""Bounded, opt-in operational notification support."""

from logintel.notifications.service import (
    NotificationService,
    NotificationSettings,
    notification_service,
)

__all__ = ["NotificationService", "NotificationSettings", "notification_service"]
