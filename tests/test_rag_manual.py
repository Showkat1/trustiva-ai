# tests/test_rag_manual.py

from app.services.evidence_extractor import EvidenceExtractor
from app.services.risk_engine import RiskEngine


TEST_CASES = [
    {
        "id": "TC01",
        "name": "Fake Bank OTP",
        "expected": "CRITICAL",
        "text": (
            "Your bank account has been suspended. "
            "Click https://secure-bank-login.com immediately "
            "and enter your OTP and password to restore access."
        ),
    },
    {
        "id": "TC02",
        "name": "Fake Government Grant",
        "expected": "HIGH",
        "text": (
            "Congratulations! You have been selected for a "
            "government grant of PKR 500,000. "
            "Pay PKR 5,000 processing charges immediately "
            "to receive your grant."
        ),
    },
    {
        "id": "TC03",
        "name": "Fake Job Registration",
        "expected": "HIGH",
        "text": (
            "You have been selected for a remote job with a salary "
            "of PKR 150,000 per month. Pay PKR 3,000 registration "
            "charges immediately to confirm your position."
        ),
    },
    {
        "id": "TC04",
        "name": "Investment Scam",
        "expected": "HIGH",
        "text": (
            "Invest PKR 20,000 today and receive guaranteed returns "
            "of PKR 60,000. Send the investment amount immediately "
            "to secure your position."
        ),
    },
    {
        "id": "TC05",
        "name": "Fake Prize",
        "expected": "HIGH",
        "text": (
            "Congratulations! You have won PKR 1,000,000 in our "
            "special prize. Pay PKR 10,000 tax and processing charges "
            "within 30 minutes to claim your prize."
        ),
    },
    {
        "id": "TC06",
        "name": "Shortened Suspicious URL",
        "expected": "HIGH",
        "text": (
            "Your account requires verification. "
            "Click https://bit.ly/secureverify immediately "
            "to continue."
        ),
    },
    {
        "id": "TC07",
        "name": "Brand Impersonation",
        "expected": "HIGH",
        "text": (
            "This is an official security notification from your bank. "
            "Your account needs urgent verification. "
            "Visit https://secure-bank-login.com to continue."
        ),
    },
    {
        "id": "TC08",
        "name": "Fake Login Page",
        "expected": "HIGH",
        "text": (
            "Your account will be blocked today. "
            "Click https://login-verification.com and sign in "
            "with your username and password."
        ),
    },
    {
        "id": "TC09",
        "name": "Urgent Payment Request",
        "expected": "HIGH",
        "text": (
            "Send PKR 15,000 immediately to complete your account "
            "verification. If payment is not received within 20 minutes, "
            "your application will be cancelled."
        ),
    },
    {
        "id": "TC10",
        "name": "Fake KYC Request",
        "expected": "HIGH",
        "text": (
            "Your KYC verification is incomplete. "
            "Send your OTP and CNIC details immediately "
            "to avoid account suspension."
        ),
    },
    {
        "id": "TC11",
        "name": "Social Engineering",
        "expected": "MEDIUM",
        "text": (
            "I am from the support team. Please confirm your identity "
            "and send the requested verification code."
        ),
    },
    {
        "id": "TC12",
        "name": "Suspicious WhatsApp Message",
        "expected": "HIGH",
        "text": (
            "Hello, I have an urgent opportunity for you. "
            "Please send PKR 5,000 now to complete the process."
        ),
    },
    {
        "id": "TC13",
        "name": "Legitimate Bank Notification",
        "expected": "LOW",
        "text": (
            "Your monthly bank statement is now available. "
            "Please log in through the official mobile application "
            "to review your statement."
        ),
    },
    {
        "id": "TC14",
        "name": "Legitimate Government Communication",
        "expected": "LOW",
        "text": (
            "The government has announced that applications for "
            "the public service program are open. "
            "Please visit the official government website for details."
        ),
    },
    {
        "id": "TC15",
        "name": "Legitimate Job Advertisement",
        "expected": "LOW",
        "text": (
            "We are hiring software engineers for our organization. "
            "Please submit your CV through the official careers page."
        ),
    },
    {
        "id": "TC16",
        "name": "Ambiguous Message",
        "expected": "LOW",
        "text": (
            "Please contact me when you have time so we can discuss "
            "the details."
        ),
    },
    {
        "id": "TC17",
        "name": "Roman Urdu Scam",
        "expected": "HIGH",
        "text": (
            "Aap ka account verify nahi hua. "
            "OTP aur PKR 5,000 abhi send karein warna account band ho jayega."
        ),
    },
    {
        "id": "TC18",
        "name": "Urdu Scam",
        "expected": "HIGH",
        "text": (
            "آپ کا اکاؤنٹ معطل ہونے والا ہے۔ "
            "اکاؤنٹ بحال کرنے کے لیے فوری طور پر 5000 روپے بھیجیں۔"
        ),
    },
    {
        "id": "TC19",
        "name": "Multi-Signal Fraud",
        "expected": "CRITICAL",
        "text": (
            "Your bank security team has detected suspicious activity. "
            "Your account will be suspended immediately. "
            "Click https://secure-bank-login.com, "
            "enter your OTP and password, and pay PKR 10,000 "
            "to restore your account."
        ),
    },
    {
        "id": "TC20",
        "name": "Benign Suspicious Keywords",
        "expected": "LOW",
        "text": (
            "The cybersecurity team published an article explaining "
            "how phishing, OTP theft, scams and social engineering work. "
            "The article recommends never sharing passwords or OTPs."
        ),
    },
]


def evaluate_case(case):
    """
    Run evidence extraction and risk scoring for one test case.
    """

    evidence = EvidenceExtractor.extract(
        case["text"]
    )

    risk = RiskEngine.calculate_risk(
        evidence["risk_indicators"],
        evidence,
    )

    passed = risk.level == case["expected"]

    return {
        "id": case["id"],
        "name": case["name"],
        "expected": case["expected"],
        "actual": risk.level,
        "score": risk.score,
        "passed": passed,
        "evidence": evidence,
        "explanation": risk.explanation,
    }


def print_case(result):
    status = "PASS" if result["passed"] else "FAIL"

    print(
        f"{result['id']} | "
        f"{status:<4} | "
        f"Expected={result['expected']:<8} | "
        f"Actual={result['actual']:<8} | "
        f"Score={result['score']:>3} | "
        f"{result['name']}"
    )

    print(
        f"     Signals: "
        f"{result['evidence']['risk_indicators']}"
    )

    print(
        f"     Categories: "
        f"{result['evidence']['categories']}"
    )

    print(
        f"     Requests: "
        f"{result['evidence']['requests']}"
    )

    print(
        f"     Explanation: "
        f"{result['explanation']}"
    )

    print("-" * 80)


def main():

    print()
    print("=" * 80)
    print("TRUSTIVA AI — EVIDENCE & RISK EVALUATION")
    print("=" * 80)
    print()

    results = []

    for case in TEST_CASES:

        result = evaluate_case(case)

        results.append(result)

        print_case(result)

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    total = len(results)

    passed = sum(
        1
        for result in results
        if result["passed"]
    )

    failed = total - passed

    accuracy = (
        (passed / total) * 100
        if total
        else 0
    )

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    print(f"Total Cases : {total}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print(f"Accuracy    : {accuracy:.1f}%")

    print()

    # ---------------------------------------------------------
    # Failed cases
    # ---------------------------------------------------------

    if failed:

        print("FAILED CASES")
        print("-" * 80)

        for result in results:

            if not result["passed"]:

                print(
                    f"{result['id']} - "
                    f"{result['name']}: "
                    f"expected {result['expected']}, "
                    f"got {result['actual']} "
                    f"({result['score']}/100)"
                )

        print()

    else:

        print(
            "ALL TEST CASES PASSED."
        )

    print("=" * 80)


if __name__ == "__main__":
    main()