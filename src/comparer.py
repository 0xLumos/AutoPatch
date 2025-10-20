def compare(before: dict, after: dict) -> dict:
    """Compare before/after vulnerability summaries."""
    result = {}
    for key in set(before.keys()).union(after.keys()):
        result[key] = {
            "before": before.get(key, 0),
            "after": after.get(key, 0),
            "reduction": before.get(key, 0) - after.get(key, 0),
        }
    return result
