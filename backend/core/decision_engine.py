from typing import List


def decide_response_level(sources: List[str], criticality: int) -> int:
    """Return 1 (observe), 2 (soft contain), or 3 (hard contain)."""
    level = 1
    unique = list({s for s in sources if s})
    if len(unique) >= 2:
        level = 2
    if level == 2 and criticality >= 4:
        level = 3
    return level
