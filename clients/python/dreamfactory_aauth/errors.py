"""Exceptions raised by the AAuth client."""

from __future__ import annotations

from typing import Any, Optional


class AAuthError(Exception):
    """An AAuth flow failed.

    ``error`` is the protocol error code (``denied``, ``invalid_scope``, ``invalid_signature``...),
    ``detail`` a human readable explanation, ``status`` the HTTP status that carried it (0 when
    the client itself refused something), ``response`` the ``requests.Response`` when there is one.
    """

    def __init__(self, error: str, detail: str = "", status: int = 0, response: Any = None, steps: Optional[list] = None):
        super().__init__(f"{error}: {detail}" if detail else error)
        self.error = error
        self.detail = detail
        self.status = status
        self.response = response
        self.steps = steps or []


class NotApproved(AAuthError):
    """The person did not approve: denied, abandoned, expired, or the wait timed out."""


class Cancelled(AAuthError):
    """The agent withdrew the pending request (on_interaction returned "cancel", or Ctrl-C)."""


class InvalidToken(AAuthError):
    """A token from the resource or the Person Server failed the client's checks."""
