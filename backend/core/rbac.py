VALID_ROLES = {"admin", "soc_analyst", "analyst", "senior_analyst", "viewer"}


def normalize_role(value: str | None) -> str | None:
    role = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if role == "soc":
        role = "soc_analyst"
    return role if role in VALID_ROLES else None
