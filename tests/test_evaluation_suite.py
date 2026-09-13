import json
from pathlib import Path

from app.services.evidence_extractor import EvidenceExtractor
from app.services.url_service import URLIntelligence
from app.services.risk_engine import assess_risk
from app.services.evidence_correlation import EvidenceCorrelation


BASE_DIR = Path(__file__).resolve().parents[1]

TEST_CASE_FILE = (
    BASE_DIR
    / "data"
    / "test_cases"
    / "trustiva_test_cases.json"
)


def load_test_cases():
    with open(
        TEST_CASE_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def main():

    test_cases = load_test_cases()

    print()
    print("=" * 80)
    print("TRUSTIVA AI — EVALUATION SUITE")
    print("=" * 80)
    print()

    total = len(test_cases)

    risk_passed = 0
    extraction_passed = 0
    correlation_detected = 0

    results = []

    for case in test_cases:

        case_id = case["id"]
        name = case["name"]
        message = case["message"]

        extracted = EvidenceExtractor.extract(
            message
        )

        # ----------------------------------------------------
        # URL ANALYSIS
        # ----------------------------------------------------

        url_results = []

        for url in extracted["urls"]:

            url_results.append(
                URLIntelligence.analyze(
                    url
                )
            )

        # ----------------------------------------------------
        # SIGNALS FROM DETERMINISTIC EXTRACTION
        # ----------------------------------------------------

        signals = list(
            extracted["risk_indicators"]
        )

        # ----------------------------------------------------
        # ADD CATEGORIES
        # ----------------------------------------------------

        signals.extend(
            extracted["categories"]
        )

        # ----------------------------------------------------
        # URL SIGNALS
        # ----------------------------------------------------

        for url_result in url_results:

            if url_result[
                "risk_indicators"
            ]:

                signals.append(
                    "suspicious_url"
                )

        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        risk_result = assess_risk(
            signals,
            extracted,
        )

        expected_risk = case[
            "expected_risk"
        ]

        risk_ok = (
            risk_result.level
            == expected_risk
        )

        if risk_ok:
            risk_passed += 1

        # ----------------------------------------------------
        # EXPECTED SIGNAL CHECK
        # ----------------------------------------------------

        normalized_actual = set(
            signals
        )

        expected_signals = set(
            case[
                "expected_signals"
            ]
        )

        missing_signals = (
            expected_signals
            - normalized_actual
        )

        extraction_ok = (
            len(missing_signals)
            == 0
        )

        if extraction_ok:
            extraction_passed += 1

        # ----------------------------------------------------
        # CORRELATION
        # ----------------------------------------------------

        correlation = (
            EvidenceCorrelation.correlate(
                extracted_evidence=extracted,
                url_results=url_results,
                ai_signals=signals,
                threat_category=case[
                    "category"
                ],
            )
        )

        if correlation[
            "correlations"
        ]:

            correlation_detected += 1

        results.append(
            {
                "id": case_id,
                "name": name,
                "expected_risk": expected_risk,
                "actual_risk": risk_result.level,
                "risk_score": risk_result.score,
                "risk_pass": risk_ok,
                "expected_signals": sorted(
                    expected_signals
                ),
                "actual_signals": sorted(
                    normalized_actual
                ),
                "missing_signals": sorted(
                    missing_signals
                ),
                "correlation": correlation[
                    "correlation_level"
                ],
            }
        )

        status = (
            "PASS"
            if risk_ok
            else "FAIL"
        )

        print(
            f"{case_id} | "
            f"{status:4} | "
            f"{risk_result.level:8} | "
            f"{risk_result.score:3}/100 | "
            f"{name}"
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    risk_accuracy = (
        risk_passed / total * 100
    )

    extraction_accuracy = (
        extraction_passed / total * 100
    )

    print()
    print("=" * 80)
    print("EVALUATION SUMMARY")
    print("=" * 80)

    print(
        f"Total Test Cases:       {total}"
    )

    print(
        f"Risk-Level Accuracy:    {risk_accuracy:.1f}%"
    )

    print(
        f"Signal Extraction:      {extraction_accuracy:.1f}%"
    )

    print(
        f"Cases With Correlation: {correlation_detected}"
    )

    print("=" * 80)

    print()
    print(
        "Note: This evaluation measures deterministic "
        "Trustiva components. AI/RAG performance will "
        "be evaluated separately."
    )


if __name__ == "__main__":
    main()