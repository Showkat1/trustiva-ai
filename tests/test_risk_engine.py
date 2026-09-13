from app.services.risk_engine import (
    assess_risk,
    normalize_signals,
)


print("=" * 70)
print("TRUSTIVA RISK ENGINE TEST")
print("=" * 70)


# ============================================================
# TEST 1 — HIGH RISK SCAM
# ============================================================

signals = [
    "Credential theft",
    "Artificial Urgency",
    "Payment Request",
    "Government Impersonation",
]

evidence = {
    "urls": [
        "https://example.com/verify"
    ],
    "phone_numbers": [
        "+923001234567"
    ],
    "money_amounts": [
        "PKR 5,000"
    ],
    "requests": [
        "OTP / verification code",
        "Payment / money transfer",
    ],
    "risk_indicators": [
        "credential_request",
        "artificial_urgency",
    ],
    "organizations": [
        "Government"
    ],
}


result = assess_risk(
    signals,
    evidence,
)


print("\nTEST 1")
print("Signals:")
print(signals)

print("\nNormalized:")
print(
    normalize_signals(
        signals
    )
)

print("\nScore:")
print(result.score)

print("\nLevel:")
print(result.level)

print("\nExplanation:")
print(result.explanation)


# ============================================================
# TEST 2 — LOW RISK
# ============================================================

signals = []

evidence = {
    "urls": [],
    "phone_numbers": [],
    "emails": [],
    "money_amounts": [],
    "requests": [],
    "risk_indicators": [],
    "organizations": [],
}


result = assess_risk(
    signals,
    evidence,
)


print("\n")
print("=" * 70)
print("TEST 2 — LOW RISK")
print("=" * 70)

print("Score:", result.score)
print("Level:", result.level)
print("Explanation:", result.explanation)


# ============================================================
# TEST 3 — OTP VARIATION
# ============================================================

signals = [
    "OTP request",
]

result = assess_risk(
    signals,
)


print("\n")
print("=" * 70)
print("TEST 3 — SIGNAL NORMALIZATION")
print("=" * 70)

print(
    "Original signal:",
    signals,
)

print(
    "Normalized:",
    normalize_signals(
        signals
    ),
)

print(
    "Score:",
    result.score,
)

print(
    "Level:",
    result.level,
)


print("\n")
print("=" * 70)
print("RISK ENGINE TEST COMPLETE")
print("=" * 70)