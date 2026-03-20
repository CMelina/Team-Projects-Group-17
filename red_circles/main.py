import math
import sys
from pathlib import Path

import cv2
import numpy as np


# Stores all metrics for a detected ring
class RingMetrics:
    def __init__(self):
        self.ringRatio = 0.0         # ratio of ring area vs outer area
        self.innerRatio = 0.0        # ratio of hole vs outer area
        self.circularity = 0.0       # how circular the contour is
        self.hasHole = 0             # whether contour has inner hole
        self.holeRatio = 0.0         # hole area / outer area
        self.centerRed = 0.0         # red fraction in center
        self.bandRed = 0.0           # red fraction in outer ring
        self.bandMinusCenter = 0.0   # difference between band and center
        self.coverage = 0.0          # how continuous the ring edge is
        self.centerPx = (0.0, 0.0)   # center of ring (x, y)
        self.radiusPx = 0.0          # radius of ring


# Creates a crop box around the detected circle
def make_crop_rect(image_size, center, radius, crop_scale):
    scaled_radius = radius * crop_scale

    left = round(center[0] - scaled_radius)
    top = round(center[1] - scaled_radius)
    width = round(2.0 * scaled_radius)
    height = round(2.0 * scaled_radius)

    img_h, img_w = image_size[:2]

    # Make sure we don’t go outside the image
    x1 = max(0, left)
    y1 = max(0, top)
    x2 = min(img_w, left + width)
    y2 = min(img_h, top + height)

    return x1, y1, max(0, x2 - x1), max(0, y2 - y1)


# Checks how much of a circle area is red
def frac_red_in_circle(mask, center, radius):
    roi = np.zeros(mask.shape, dtype=np.uint8)

    # Draw a filled circle
    cv2.circle(roi, (round(center[0]), round(center[1])), round(radius), 255, -1)

    denom = cv2.countNonZero(roi)
    if denom == 0:
        return 0.0

    # Count how many pixels are both red AND inside circle
    both = cv2.bitwise_and(mask, roi)

    return float(cv2.countNonZero(both)) / float(denom)


# Checks how much of a ring area is red
def red_fraction_in_ring(mask, center, r_inner, r_outer):
    outer = np.zeros(mask.shape, dtype=np.uint8)
    inner = np.zeros(mask.shape, dtype=np.uint8)

    # Draw outer and inner circles
    cv2.circle(outer, (round(center[0]), round(center[1])), round(r_outer), 255, -1)
    cv2.circle(inner, (round(center[0]), round(center[1])), round(r_inner), 255, -1)

    # Subtract inner from outer to get ring
    annulus = cv2.subtract(outer, inner)

    denom = cv2.countNonZero(annulus)
    if denom == 0:
        return 0.0

    both = cv2.bitwise_and(mask, annulus)

    return float(cv2.countNonZero(both)) / float(denom)


# Checks how complete the ring edge is (samples points around it)
def ring_edge_coverage(mask, center, radius, samples=180):
    if samples <= 0:
        return 0.0

    hits = 0
    h, w = mask.shape[:2]

    # Sample points along circle perimeter
    for i in range(samples):
        angle = 2.0 * math.pi * i / samples
        x = round(center[0] + radius * math.cos(angle))
        y = round(center[1] + radius * math.sin(angle))

        # Count if that point is red
        if 0 <= x < w and 0 <= y < h and mask[y, x] > 0:
            hits += 1

    return float(hits) / float(samples)


# Creates a binary mask of red regions on image
def create_red_mask(bgr):
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)

    # Red is split in HSV, so we use two ranges
    m1 = cv2.inRange(hsv, (0, 50, 50), (10, 255, 255))
    m2 = cv2.inRange(hsv, (170, 50, 50), (180, 255, 255))

    mask = cv2.bitwise_or(m1, m2)

    # Clean up noise
    k3 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
    k5 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))

    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, k3)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, k5)

    return mask


# Finds the best ring-like shape on the image
def extract_ring_metrics(bgr):
    if bgr is None or bgr.size == 0:
        return False, None

    mask = create_red_mask(bgr)

    contours_info = cv2.findContours(mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    contours, hierarchy = contours_info[-2], contours_info[-1]

    if not contours or hierarchy is None:
        return False, None

    hierarchy = hierarchy[0]

    best_idx = -1
    best_score = -1.0

    # Look through all shapes and pick the best one
    for i, contour in enumerate(contours):
        area = abs(cv2.contourArea(contour))
        if area < 100:
            continue

        perimeter = cv2.arcLength(contour, True)
        if perimeter <= 0:
            continue

        circularity = 4.0 * math.pi * area / (perimeter * perimeter)

        # Bonus if it has a hole (rings should)
        child = hierarchy[i][2]
        hole_bonus = 0.15 if child >= 0 else 0.0

        score = math.log(area + 1.0) + 2.0 * circularity + hole_bonus

        if score > best_score:
            best_score = score
            best_idx = i

    if best_idx < 0:
        return False, None

    metrics = RingMetrics()

    outer_area = abs(cv2.contourArea(contours[best_idx]))
    outer_per = cv2.arcLength(contours[best_idx], True)

    metrics.circularity = 4.0 * math.pi * outer_area / (outer_per * outer_per)

    # Check if it has a hole
    child_idx = hierarchy[best_idx][2]
    if child_idx >= 0:
        metrics.hasHole = 1
        hole_area = abs(cv2.contourArea(contours[child_idx]))

        metrics.holeRatio = hole_area / outer_area
    else:
        metrics.hasHole = 0

    # Get circle position and size
    (cx, cy), radius = cv2.minEnclosingCircle(contours[best_idx])

    if radius <= 2:
        return False, None

    metrics.centerPx = (cx, cy)
    metrics.radiusPx = radius

    # Measure red in center vs ring
    metrics.centerRed = frac_red_in_circle(mask, metrics.centerPx, 0.30 * radius)
    metrics.bandRed = red_fraction_in_ring(mask, metrics.centerPx, 0.70 * radius, radius)
    metrics.bandMinusCenter = metrics.bandRed - metrics.centerRed

    # Check how complete the ring is
    metrics.coverage = ring_edge_coverage(mask, metrics.centerPx, 0.85 * radius)

    return True, metrics


# Decides if the detected shape is a valid ring
# These values were pulled from the 3 provided test images
def is_valid_ring(metrics):
    if metrics.hasHole != 1:
        return False
    if metrics.circularity < 0.80:
        return False
    if metrics.holeRatio < 0.55 or metrics.holeRatio > 0.85:
        return False
    if metrics.bandRed < 0.45:
        return False
    if metrics.centerRed > 0.10:
        return False
    if metrics.bandMinusCenter < 0.35:
        return False
    if metrics.coverage < 0.55:
        return False
    return True


def main():
    print("Running red circle detection...")

    # Expect input folder, output folder, and crop size
    if len(sys.argv) < 4:
        print("Usage: script <input_dir> <crops_dir> <crop_scale>")
        return 2

    input_dir = Path(sys.argv[1])
    crops_dir = Path(sys.argv[2])
    crop_scale = float(sys.argv[3])

    if not input_dir.exists():
        print("Input folder not found")
        return 2

    crops_dir.mkdir(parents=True, exist_ok=True)

    total = 0
    yes = 0
    no = 0

    # Go through all images
    for path in input_dir.iterdir():
        if not path.is_file():
            continue

        total += 1

        img = cv2.imread(str(path))
        if img is None:
            no += 1
            continue

        ok, metrics = extract_ring_metrics(img)

        if not ok or not is_valid_ring(metrics):
            no += 1
            continue

        # Crop the detected ring
        x, y, w, h = make_crop_rect(img.shape, metrics.centerPx, metrics.radiusPx, crop_scale)

        if w <= 0 or h <= 0:
            no += 1
            continue

        cropped = img[y:y+h, x:x+w]

        out_path = crops_dir / f"{path.stem}_crop.png"

        if not cv2.imwrite(str(out_path), cropped):
            no += 1
            continue

        print(f"{path.name} was detected.")
        yes += 1

    print(f"\nDone. Processed={total} YES={yes} NO={no}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())