"""
Reversible Tokenization Vault — Session-Consistent De-Identification & Re-Identification
========================================================================================
Thread-safe, bounded in-memory tokenization vault supporting two-way de-identification
on ingress and re-identification on egress for authorized banking services under
BCB CMN 4893/21 and LGPD (Lei 13.709/2018).
"""

import time
import threading
from typing import Dict, Optional, Tuple, List
from collections import OrderedDict


class SessionVault:
    """Stores bidirectional mappings between original values and replacements for a single session."""

    def __init__(self, session_id: str):
        self.session_id: str = session_id
        # forward: canonical_key -> base_synthetic
        self.forward_map: Dict[str, str] = {}
        # reverse: replacement_string -> original_value
        self.reverse_map: Dict[str, str] = {}
        self.created_at: float = time.time()
        self.last_accessed: float = time.time()

    def record_entity(self, canonical_key: str, original: str, replacement: str):
        """Records both forward mapping for generation and reverse mapping for re-identification."""
        self.last_accessed = time.time()
        self.forward_map[canonical_key] = replacement
        self.reverse_map[replacement] = original

    def restore_text(self, text: str) -> Tuple[str, int]:
        """
        Substitutes all recorded replacement tokens or synthetic values back to originals.
        Sorts replacements by length descending to prevent partial substring collision.
        """
        self.last_accessed = time.time()
        if not self.reverse_map:
            return text, 0

        restored = text
        count = 0
        # Sort by length descending to avoid partial replacement overlaps
        sorted_replacements = sorted(self.reverse_map.keys(), key=len, reverse=True)

        for rep in sorted_replacements:
            if rep in restored:
                occurrences = restored.count(rep)
                restored = restored.replace(rep, self.reverse_map[rep])
                count += occurrences

        return restored, count


class TokenVault:
    """Thread-safe, LRU-bounded tokenization vault managing multi-session mappings."""

    def __init__(self, max_sessions: int = 1000):
        self.max_sessions: int = max_sessions
        self._sessions: OrderedDict[str, SessionVault] = OrderedDict()
        self._lock = threading.Lock()

    def get_or_create_session(self, session_id: str) -> SessionVault:
        with self._lock:
            if session_id in self._sessions:
                self._sessions.move_to_end(session_id)
                return self._sessions[session_id]

            if len(self._sessions) >= self.max_sessions:
                # Evict oldest session (LRU)
                self._sessions.popitem(last=False)

            session = SessionVault(session_id)
            self._sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[SessionVault]:
        with self._lock:
            if session_id in self._sessions:
                self._sessions.move_to_end(session_id)
                return self._sessions[session_id]
            return None

    def record_entity(self, session_id: str, canonical_key: str, original: str, replacement: str):
        session = self.get_or_create_session(session_id)
        session.record_entity(canonical_key, original, replacement)

    def reidentify(self, session_id: str, text: str) -> Tuple[str, int]:
        session = self.get_session(session_id)
        if not session:
            return text, 0
        return session.restore_text(text)

    def reset_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def clear(self):
        with self._lock:
            self._sessions.clear()

    @property
    def active_sessions_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    @property
    def total_tokens_count(self) -> int:
        with self._lock:
            return sum(len(s.reverse_map) for s in self._sessions.values())


# Global default vault instance
GLOBAL_TOKEN_VAULT = TokenVault(max_sessions=1000)
