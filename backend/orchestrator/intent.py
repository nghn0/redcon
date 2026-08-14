"""Intent classification for the orchestrator's top-level interaction modes.

This module deliberately does not select a tool or inspect the candidate-action
menu.  Its only job is to make the mutually exclusive routing decision that
must happen before the investigation planner is allowed to prepare work.
"""

from __future__ import annotations

import re


CONVERSATION = "conversation"
PLAN = "plan"
EXECUTION = "execution"

# These phrases are questions about method, not permission to start work.  They
# take precedence over execution words that may appear in the same message
# (for example: "How would you scan example.com?").
_PLANNING_PATTERNS = (
    r"\bhow\s+(?:would|should|do)\s+(?:you|i)\b",
    r"\bwhat\s+(?:is|are)\s+your\s+(?:approach|plan|steps)\b",
    r"\bwhat\s+steps\s+would\s+you\s+take\b",
    r"\b(?:approach|strategy|methodology|plan)\b",
    r"\bwalk\s+me\s+through\b",
    r"\b(before|later)\b.*\b(?:run|scan|execute|test)\b",
)

_CONVERSATION_PATTERNS = (
    r"^\s*(?:what\s+can\s+you\s+do|what\s+tools?\s+do\s+you\s+have)\s*\??\s*$",
    r"^\s*what\s+is\b",
    r"^\s*(?:explain|why|how\s+does|what\s+happened)\b",
    r"\b(?:tell|show)\s+me\s+(?:about|the|what)\b",
)

# Execution requires an imperative/request to perform work now.  A bare tool
# name, a target URL, or a statement of interest is intentionally insufficient.
_EXECUTION_PATTERN = re.compile(
    r"(?:^|\b)(?:scan|run|execute|enumerate|launch|start\s+(?:testing|assessment|recon(?:naissance)?|scanning)|"
    r"begin\s+(?:assessment|testing|recon(?:naissance)?|scan(?:ning)?)|perform\s+(?:recon(?:naissance)?|an\s+assessment|testing)|"
    r"test|probe|discover|map)\b",
    re.IGNORECASE,
)

_CONTINUE_PATTERN = re.compile(r"^\s*(?:continue|go\s+on|next|proceed)\s*[!.]?\s*$", re.IGNORECASE)


def classify_intent(message: str | None, session: dict | None = None) -> str:
    """Return ``conversation``, ``plan``, or ``execution``.

    A continuation with no user message is execution only for an already
    auto-driven investigation.  User-originated text defaults to conversation
    when it is ambiguous; this makes starting a scan an explicit act.
    """
    if not message or not message.strip():
        if session and session.get("auto_drive"):
            return EXECUTION
        return CONVERSATION

    text = message.strip().lower()
    if any(re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in _PLANNING_PATTERNS):
        return PLAN
    if any(re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in _CONVERSATION_PATTERNS):
        return CONVERSATION
    if _CONTINUE_PATTERN.match(text) and session and any(
        entry.get("type") == "action" for entry in session.get("action_history", [])
    ):
        return EXECUTION
    if _EXECUTION_PATTERN.search(text):
        return EXECUTION
    return CONVERSATION
