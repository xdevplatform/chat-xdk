"""Many signed-in users in one process.

A chat holds one user's private keys and signs as that user. A process that
serves several signed-in users keeps one chat per user, for all of that
user's conversations, and never one per conversation: the chat keeps its
conversation keys by conversation and the public keys it has met by user id.

Other users' public keys are the same whichever chat asks, so the chats share
one hook that fetches them:

* ``SharedPublicKeys`` -> the hook, ``resolve``, over one cache of
                          ``GET /2/users/{id}/public_keys`` answers
* ``UserChats``        -> one ``ChatCore`` per signed-in user, each with that
                          hook

Both are safe to use from several threads.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future
from typing import Any, Callable

from chat_core import ChatCore

logger = logging.getLogger("chatbot")

# How long a fetched answer is served before it is fetched again, in seconds.
PUBLIC_KEYS_TTL_SECONDS = 300.0

# One user's records, as GET /2/users/{id}/public_keys returns them.
Records = list[dict[str, Any]]


class _Lookup:
    """One user's lookup. ``records`` completes with the user's records, or
    with ``None`` when the fetch failed. ``expires`` is the time on the clock
    at which the answer stops being served."""

    def __init__(self, expires: float) -> None:
        self.records: Future[Records | None] = Future()
        self.expires = expires


class SharedPublicKeys:
    """A public-key hook for every chat in the process.

    ``resolve`` is the hook: it takes user ids and returns each user's
    records, by user id. ``fetch(user_id)`` returns one user's records, as
    ``GET /2/users/{id}/public_keys`` returns them. Its answers are kept by
    user id, so the chats of two signed-in users who meet the same user cost
    one request:

    * Calls that ask for a user whose lookup is under way wait for that
      lookup.
    * A lookup that fails is logged and dropped, and the user is left out of
      the answer: the next call fetches again.
    * An answer is served for ``ttl_seconds``, then fetched again, so a key a
      user registers later is picked up.

    ``clock`` returns the time in seconds. ``resolve`` may be called from
    several threads at once: lookups of different users do not wait for each
    other.
    """

    def __init__(
        self,
        fetch: Callable[[str], Records],
        ttl_seconds: float = PUBLIC_KEYS_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        # Guards _lookups. It is never held while a fetch runs.
        self._lock = threading.Lock()
        self._lookups: dict[str, _Lookup] = {}

    def resolve(self, user_ids: list[str]) -> dict[str, Records]:
        """The records of each of ``user_ids``, by user id, without the users
        whose lookup failed."""
        records = {}
        for user_id in user_ids:
            found = self._look_up(user_id)
            if found is not None:
                records[user_id] = found
        return records

    def _look_up(self, user_id: str) -> Records | None:
        """One user's records, from the cache or fetched, or ``None`` when
        the fetch failed."""
        at = self._clock()
        with self._lock:
            lookup = self._lookups.get(user_id)
            fetching = lookup is None or lookup.expires <= at
            if fetching:
                # Answers past their time go here, so the cache holds no
                # more than the users looked up within one TTL.
                expired = [
                    cached_id
                    for cached_id, cached in self._lookups.items()
                    if cached.expires <= at
                ]
                for cached_id in expired:
                    del self._lookups[cached_id]
                lookup = _Lookup(at + self._ttl_seconds)
                self._lookups[user_id] = lookup
        if fetching:
            self._fetch_into(lookup, user_id)
        # A lookup another call started completes when that call's fetch
        # returns.
        return lookup.records.result()

    def _fetch_into(self, lookup: _Lookup, user_id: str) -> None:
        """Fetch the records of ``user_id`` and complete ``lookup`` with
        them, which releases the calls waiting for it."""
        try:
            records = self._fetch(user_id)
        except BaseException as err:
            # The lookup is not kept, so the next call fetches again, and the
            # calls waiting for it get no records.
            with self._lock:
                if self._lookups.get(user_id) is lookup:
                    del self._lookups[user_id]
            lookup.records.set_result(None)
            # A fetch that failed is logged. What interrupts the thread, such
            # as KeyboardInterrupt, is no Exception and goes on to the caller.
            if not isinstance(err, Exception):
                raise
            logger.warning("public_keys_fetch_failed user=%s err=%s", user_id, err)
            return
        lookup.records.set_result(records)


class UserChats:
    """One chat per signed-in user, all with one public-key hook."""

    def __init__(self, resolve_public_keys: Callable[[list[str]], dict[str, Records]]) -> None:
        """``resolve_public_keys`` is the hook every chat shares:
        ``SharedPublicKeys.resolve``."""
        self._resolve_public_keys = resolve_public_keys
        # Guards _chats.
        self._lock = threading.Lock()
        self._chats: dict[str, ChatCore] = {}

    def chat_for(self, user_id: str, private_keys_b64: str, signing_key_version: str) -> ChatCore:
        """The chat of the signed-in user ``user_id``, created on first use
        from the user's private-key blob and the ``public_key_version`` it
        was registered under.

        Calls for one user get one chat, from any thread, and that chat
        serves every conversation of the user. A chat that could not be
        created is not kept: the next call tries again.
        """
        with self._lock:
            chat = self._chats.get(user_id)
            if chat is None:
                # Created under the lock, so two calls for one user cannot
                # make two chats. Creating a chat waits for no request.
                chat = self._open(user_id, private_keys_b64, signing_key_version)
                self._chats[user_id] = chat
            return chat

    def _open(self, user_id: str, private_keys_b64: str, signing_key_version: str) -> ChatCore:
        core = ChatCore()
        try:
            core.load_keys(private_keys_b64, signing_key_version)
            core.set_identity(user_id)
            # Setting the hook also turns the SDK's key cache on.
            core.resolve_public_keys_with(self._resolve_public_keys)
        except Exception:
            core.close()
            raise
        return core

    def close(self, user_id: str) -> None:
        """Sign ``user_id`` out: forget the user's chat and clear its keys
        from memory."""
        with self._lock:
            chat = self._chats.pop(user_id, None)
        if chat is not None:
            chat.close()
