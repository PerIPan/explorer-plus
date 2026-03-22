"""
Sector extractor — maps MITRE ATT&CK threat groups to industry sectors via
keyword matching against group descriptions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _load_sectors(sectors_path: str) -> dict[str, list[str]]:
    """Load sector keyword map from JSON file.

    Args:
        sectors_path: Path to sectors.json.

    Returns:
        Dict mapping sector name to list of regex-compatible keyword patterns.
    """
    with open(sectors_path, encoding='utf-8') as fh:
        return json.load(fh)


def _make_slug(sector_name: str) -> str:
    """Convert a sector name to a URL-safe slug.

    Examples:
        'Government' -> 'government'
        'Supply Chain' -> 'supply-chain'

    Args:
        sector_name: Human-readable sector name.

    Returns:
        Lowercase hyphen-separated slug string.
    """
    return sector_name.lower().replace(' ', '-')


def extract_sectors(
    groups: list[dict[str, Any]],
    sectors_path: str = 'seed/sectors.json',
) -> list[dict[str, Any]]:
    """Scan group descriptions against sector keyword patterns.

    Each group dict must contain at minimum 'attack_id' and 'description'.
    Groups with a None or empty description are skipped.

    For each (group, sector) pair where at least one keyword matches the
    description, one result dict is emitted containing all matched keywords.

    Args:
        groups: List of group dicts from extract.py, each having 'attack_id',
            'name', and 'description' keys.
        sectors_path: Path to sectors.json keyword map.

    Returns:
        List of dicts, each with keys:
            - group_attack_id (str): e.g. 'G0016'
            - sector_name (str): e.g. 'Government'
            - sector_slug (str): e.g. 'government'
            - matched_keywords (list[str]): keywords that matched
            - source (str): always 'auto'
    """
    sector_map = _load_sectors(sectors_path)
    results: list[dict[str, Any]] = []

    for group in groups:
        description: str | None = group.get('description')
        if not description or not description.strip():
            continue

        attack_id: str = group['attack_id']

        for sector_name, keywords in sector_map.items():
            matched: list[str] = [
                kw
                for kw in keywords
                if re.search(kw, description, re.IGNORECASE)
            ]
            if matched:
                results.append({
                    'group_attack_id': attack_id,
                    'sector_name': sector_name,
                    'sector_slug': _make_slug(sector_name),
                    'matched_keywords': matched,
                    'source': 'auto',
                })

    return results


def get_sector_list(sectors_path: str = 'seed/sectors.json') -> list[dict[str, str]]:
    """Return a list of all sectors defined in the keyword map.

    Args:
        sectors_path: Path to sectors.json.

    Returns:
        List of dicts with 'name' and 'slug' keys, one per sector.
    """
    sector_map = _load_sectors(sectors_path)
    return [
        {'name': name, 'slug': _make_slug(name)}
        for name in sector_map
    ]
