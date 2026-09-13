from app.services.evidence_extractor import (
    EvidenceExtractor,
)


test_message = """
Congratulations! You have been selected for
a government financial assistance program.

You will receive PKR 500,000.

To release the payment, send PKR 5,000
verification fee immediately.

Also send your OTP to 03001234567.

Visit:
https://example.com/verify

Your account will be blocked within 30 minutes
if you do not complete the process.
"""


result = EvidenceExtractor.extract(
    test_message
)


print("\n")
print("=" * 70)
print("TRUSTIVA EVIDENCE EXTRACTION TEST")
print("=" * 70)


for key, value in result.items():

    print(f"\n{key.upper()}:")

    for item in value:

        print(f"  • {item}")


print("\n")