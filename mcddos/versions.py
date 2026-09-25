"""Protocol versions for Minecraft Java 1.16 -> 26.3 (releases)."""

VERSIONS = {
    "1.16": 735, "1.16.1": 736, "1.16.2": 751, "1.16.3": 753, "1.16.4": 754,
    "1.16.5": 754,
    "1.17": 755, "1.17.1": 756,
    "1.18": 757, "1.18.1": 757, "1.18.2": 758,
    "1.19": 759, "1.19.1": 760, "1.19.2": 760, "1.19.3": 761, "1.19.4": 762,
    "1.20": 763, "1.20.1": 763, "1.20.2": 764, "1.20.3": 765, "1.20.4": 765,
    "1.20.5": 766, "1.20.6": 766,
    "1.21": 767, "1.21.1": 767, "1.21.2": 768, "1.21.3": 768, "1.21.4": 769,
    "1.21.5": 770, "1.21.6": 771, "1.21.7": 772, "1.21.8": 772, "1.21.9": 773,
    "1.21.10": 773, "1.21.11": 774,
    "26.1": 775, "26.1.1": 775, "26.1.2": 775,
    "26.2": 776,
    "26.3": 777,
}

MIN_PV, MAX_PV = 735, 777


def protocol_of(version: str) -> int:
    v = version.strip()
    if v in VERSIONS:
        return VERSIONS[v]
    if v.isdigit():
        p = int(v)
        if MIN_PV <= p <= MAX_PV:
            return p
    raise ValueError(f"unknown version '{version}' (expected like 1.16, 1.20.4, 1.21, 26.3 or protocol number 735-777)")


def guess_version_for_protocol(pvn: int):
    """Best release name for a protocol number."""
    best = None
    for name, p in VERSIONS.items():
        if p == pvn:
            best = name
    return best or f"protocol {pvn}"


def is_1_16_2_plus(pvn: int) -> bool:
    return pvn >= 751
