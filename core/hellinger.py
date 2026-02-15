"""
sky-shield/core/hellinger.py

Hellinger Distance Calculation
==============================
Core detection logic of sky shield.

The Hellinger distance measures divergence between two probability
distributions P (baseline sketch) and Q (current sketch).

Formula:
    H(P, Q) = (1/√2) * √(Σ (√p_i - √q_i)²)

Range: [0, 1]
  - 0.0 = identical distributions (no attack)
  - 1.0 = completely different distributions (maximum divergence)

SkyShield's key innovation: compute H per-row across the sketch matrix
and average them, which reduces the impact of network dynamics and
improves detection accuracy vs. using a single flat distribution.
"""

import numpy as np
import core.sketch as sketch
from config import HELLINGER_THRESHOLD

def hellinger_distance(p: np.ndarray, q: np.ndarray) -> float:
    """
    Compute the Hellinger distance between two 1D probability distributions P and Q.

    Args :
        P (np.array): Baseline distribution (from sketch).
        Q (np.array): Current distribution (from sketch).
    Returns:
        float: Hellinger distance in the range [0.0, 1.0].
    """
    p = np.clip(p, 0, None)
    q = np.clip(q, 0, None)
    sqrt_diff = np.sqrt(p) - np.sqrt(q)
    h = (1.0 / np.sqrt(2.0)) * np.sqrt(np.sum(sqrt_diff ** 2))
    return float(np.clip(h, 0.0, 1.0))

def sketch_divergence(baseline: sketch.Sketch, current: sketch.Sketch) -> dict:
    """
    Compute divergence between two sketches across all rows.
    SkyShield computes Hellinger distance per row and averages them.
    This multi-row approach is more robust than a single distribution
    comparison, as discussed in Section IV of the paper.

    Args:
        baseline: the reference sketch (taken at start of window)
        current:  the live/updated sketch

    Returns:
        dict with:
          'distance'   : float [0,1] — average Hellinger across rows
          'per_row'    : list of floats — H distance per sketch row
          'is_attack'  : bool — True if distance exceeds threshold
          'severity'   : str — 'NORMAL', 'SUSPICIOUS', 'ATTACK'
    """
    baseline_dist = baseline.get_distribution()
    current_dist = current.get_distribution()

    per_row_distances = []
    for row in range(baseline.rows):
        d = hellinger_distance(baseline_dist[row], current_dist[row])
        per_row_distances.append(d)
    
    avg_distance = float(np.mean(per_row_distances))
    is_attack = avg_distance >= HELLINGER_THRESHOLD

    # Severity Levels
    if avg_distance < 0.15:
        severity = 'NORMAL'
    elif avg_distance < HELLINGER_THRESHOLD:
        severity = 'SUSPICIOUS'
    else:
        severity = 'ATTACK'
    
    return {
        'distance': round(avg_distance, 4),
        'per_row': [round(d, 4) for d in per_row_distances],
        'is_attack': is_attack,
        'severity': severity,
        'threshold': HELLINGER_THRESHOLD,
    }

def incremental_divergence(baseline: sketch.Sketch, current: sketch.Sketch) -> float:
    """
    Fast single-value divergence check, used for real-time monitoring.
    Returns just the scalar Hellinger distance.
    """
    result = sketch_divergence(baseline, current)
    return result["distance"]


def explain_divergence(result: dict) -> str:
    """Human-readable explanation of a divergence result."""
    d = result["distance"]
    severity = result["severity"]
    lines = [
        f"[{severity}] Hellinger Distance: {d:.4f} (threshold: {result['threshold']})",
        f"  Per-row distances: {result['per_row']}",
    ]
    if result["is_attack"]:
        lines.append(
            f"  ⚠ Attack detected! Distribution divergence ({d:.4f}) exceeds threshold."
        )
    else:
        lines.append(f"  ✓ Traffic appears normal.")
    return "\n".join(lines)