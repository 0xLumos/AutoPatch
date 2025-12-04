def compare(before: dict, after: dict) -> dict:
    out = {}
    for k in before.keys():
        out[k] = {
            "before": before[k],
            "after": after[k],
            "reduction": before[k] - after[k]
        }
    return out
