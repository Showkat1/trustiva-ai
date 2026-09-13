from app.services.evidence_correlation import (
    EvidenceCorrelation,
)


# ============================================================
# TEST SCENARIO
# ============================================================

extracted_evidence = {

    "urls": [
        "https://secure-hbl-login.example.com/verify"
    ],

    "phone_numbers": [
        "+923001234567"
    ],

    "emails": [],

    "money_amounts": [
        "PKR 500,000",
        "PKR 5,000",
    ],

    "organizations": [
        "HBL"
    ],

    "requests": [
        "OTP / verification code",
        "Payment / money transfer",
    ],

    "risk_indicators": [
        "credential_request",
        "artificial_urgency",
        "advance_payment",
    ],

    "categories": [
        "government_impersonation",
    ],
}


# ============================================================
# URL RESULTS
# ============================================================

url_results = [

    {
        "url":
            "https://secure-hbl-login.example.com/verify",

        "hostname":
            "secure-hbl-login.example.com",

        "registered_domain":
            "example.com",

        "risk_indicators": [
            "suspicious_url_keywords",
            "brand_domain_mismatch",
        ],

        "brand_mentions": [
            "hbl"
        ],

        "brand_domain_mismatches": [
            "hbl"
        ],
    }

]


# ============================================================
# AI SIGNALS
# ============================================================

ai_signals = [

    "Credential theft",
    "Artificial Urgency",
    "Payment Request",
    "Government Impersonation",

]


# ============================================================
# RUN CORRELATION
# ============================================================

result = EvidenceCorrelation.correlate(

    extracted_evidence=extracted_evidence,

    url_results=url_results,

    ai_signals=ai_signals,

    threat_category="Government Impersonation",

)


# ============================================================
# DISPLAY
# ============================================================

print("\n")
print("=" * 80)
print("TRUSTIVA EVIDENCE CORRELATION TEST")
print("=" * 80)


print("\nEVIDENCE SIGNALS:")

for signal in result[
    "evidence_signals"
]:

    print(
        f"  • {signal}"
    )


print("\nCORRELATION SCORE:")

print(
    result[
        "correlation_score"
    ]
)


print("\nCORRELATION LEVEL:")

print(
    result[
        "correlation_level"
    ]
)


print("\nCORRELATIONS:")

for correlation in result[
    "correlations"
]:

    print(
        f"\n  {correlation['name']}"
    )

    print(
        f"  Severity: "
        f"{correlation['severity']}"
    )

    print(
        f"  Explanation: "
        f"{correlation['explanation']}"
    )

    print(
        "  Evidence: "
        + ", ".join(
            correlation[
                "evidence"
            ]
        )
    )


print("\nRELATIONSHIPS:")

for relationship in result[
    "relationships"
]:

    print(
        f"  {relationship['source']} "
        f"--[{relationship['relationship']}]--> "
        f"{relationship['target']}"
    )


print("\nNARRATIVE:")

print(
    result[
        "narrative"
    ]
)


print("\n")
print("=" * 80)
print("EVIDENCE CORRELATION TEST COMPLETE")
print("=" * 80)