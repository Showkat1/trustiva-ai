# app/services/risk_engine.py

from typing import Any, Dict, Iterable, List, Optional

from app.models.risk import RiskResult


class RiskEngine:
    """
    Explainable risk engine for Trustiva AI.

    Design principles
    -----------------
    1. Do not treat every signal as independent evidence.
    2. Category labels such as phishing, job_scam, investment_scam,
       prize_scam and social_engineering are contextual classifications,
       not automatically additional high-weight evidence.
    3. Strong technical evidence can elevate a case to CRITICAL.
    4. Payment + urgency should normally be HIGH, not CRITICAL.
    5. Credential + suspicious URL is substantially stronger.
    6. Known threat intelligence or contradicted trusted claims can
       justify CRITICAL when corroborated.
    7. Unknown sender/number does NOT mean fraudulent.
    8. The final score is capped according to evidence strength.
    """

    # =========================================================
    # Core behavioral / technical weights
    # =========================================================

    WEIGHTS = {
        # Direct harmful actions
        "credential_request": 25,
        "advance_payment": 20,

        # Pressure / manipulation
        "artificial_urgency": 10,

        # Technical indicators
        "suspicious_url": 20,
        "url_present": 5,

        # Identity / impersonation
        "impersonation": 15,
        "government_impersonation": 15,
        "unverified_identity": 8,

        # Threat intelligence / verification
        "known_threat_indicator": 30,
        "contradicted_claim": 30,

        # Contextual threat classifications
        "phishing": 8,
        "social_engineering": 6,
        "job_scam": 8,
        "investment_scam": 8,
        "prize_scam": 8,
    }

    # =========================================================
    # Evidence bonuses
    # =========================================================

    EVIDENCE_BONUSES = {
        "url": 5,
        "phone": 2,
        "email": 2,
        "money": 5,
        "credential": 5,
        "organization": 2,
    }

    # =========================================================
    # Thresholds
    # =========================================================

    MEDIUM_THRESHOLD = 25
    HIGH_THRESHOLD = 50
    CRITICAL_THRESHOLD = 80

    # =========================================================
    # Utilities
    # =========================================================

    @staticmethod
    def _normalize_signals(
        signals: Optional[Iterable[str]],
    ) -> List[str]:
        """
        Normalize signal names and remove duplicates.
        """

        if not signals:
            return []

        result = []

        for signal in signals:
            if signal is None:
                continue

            value = str(signal).strip().lower()

            if value and value not in result:
                result.append(value)

        return result

    @staticmethod
    def _safe_len(value: Any) -> int:
        """
        Safely return collection length.
        """

        if value is None:
            return 0

        try:
            return len(value)
        except TypeError:
            return 0

    # =========================================================
    # Evidence classification
    # =========================================================

    @classmethod
    def _has_payment(
        cls,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> bool:

        if "advance_payment" in signals:
            return True

        if not evidence:
            return False

        requests = evidence.get("requests", [])
        money = evidence.get("money_amounts", [])

        payment_request = any(
            "payment" in str(item).lower()
            or "money" in str(item).lower()
            or "transfer" in str(item).lower()
            for item in requests
        )

        return payment_request or bool(money)

    @classmethod
    def _has_credentials(
        cls,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> bool:

        if "credential_request" in signals:
            return True

        if not evidence:
            return False

        requests = evidence.get("requests", [])

        return any(
            any(
                term in str(item).lower()
                for term in [
                    "otp",
                    "password",
                    "pin",
                    "credential",
                    "verification code",
            ]
            )
            for item in requests
        )

    @classmethod
    def _has_url(
        cls,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> bool:

        if (
            "suspicious_url" in signals
            or "url_present" in signals
        ):
            return True

        if not evidence:
            return False

        return bool(evidence.get("urls", []))

    @classmethod
    def _has_money(
        cls,
        evidence: Optional[Dict[str, Any]],
    ) -> bool:

        if not evidence:
            return False

        return bool(evidence.get("money_amounts", []))

    @classmethod
    def _has_organization(
        cls,
        evidence: Optional[Dict[str, Any]],
    ) -> bool:

        if not evidence:
            return False

        return bool(evidence.get("organizations", []))

    # =========================================================
    # Strong CRITICAL evidence
    # =========================================================

    @classmethod
    def _critical_reason(
        cls,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> Optional[str]:
        """
        Determine whether there is enough independent evidence
        to justify CRITICAL.

        CRITICAL should be difficult to reach.
        """

        has_payment = cls._has_payment(
            signals,
            evidence,
        )

        has_credentials = cls._has_credentials(
            signals,
            evidence,
        )

        has_url = cls._has_url(
            signals,
            evidence,
        )

        has_money = cls._has_money(
            evidence,
        )

        has_impersonation = (
            "impersonation" in signals
            or "government_impersonation" in signals
        )

        # -----------------------------------------------------
        # Known malicious / contradicted intelligence
        # -----------------------------------------------------

        if "known_threat_indicator" in signals:
            return (
                "Known threat intelligence strongly "
                "corroborates the detected risk."
            )

        if "contradicted_claim" in signals:
            return (
                "A material claim was contradicted by "
                "trusted verification evidence."
            )

        # -----------------------------------------------------
        # Credential theft through suspicious URL
        # -----------------------------------------------------

        if (
            has_credentials
            and has_url
            and (
                "suspicious_url" in signals
                or "phishing" in signals
            )
        ):
            return (
                "Credential-request behavior is combined "
                "with suspicious link or phishing evidence."
            )

        # -----------------------------------------------------
        # Credential + payment + suspicious URL
        # -----------------------------------------------------

        if (
            has_credentials
            and has_payment
            and has_url
        ):
            return (
                "Credential theft, payment request and "
                "suspicious URL evidence are independently "
                "correlated."
            )

        # -----------------------------------------------------
        # Government impersonation + credential + URL
        # -----------------------------------------------------

        if (
            "government_impersonation" in signals
            and has_credentials
            and has_url
        ):
            return (
                "Government impersonation is combined with "
                "credential harvesting and suspicious URL evidence."
            )

        # -----------------------------------------------------
        # Multiple independent evidence classes
        # -----------------------------------------------------

        independent_classes = 0

        if has_credentials:
            independent_classes += 1

        if has_payment:
            independent_classes += 1

        if "suspicious_url" in signals:
            independent_classes += 1

        if "known_threat_indicator" in signals:
            independent_classes += 1

        if "contradicted_claim" in signals:
            independent_classes += 1

        if "government_impersonation" in signals:
            independent_classes += 1

        if (
            independent_classes >= 4
            and has_money
        ):
            return (
                "Multiple independent financial, identity and "
                "technical indicators are correlated."
            )

        return None

    # =========================================================
    # Correlation bonuses
    # =========================================================

    @classmethod
    def _correlation_bonus(
        cls,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> int:
        """
        Add modest bonuses for meaningful combinations.

        These bonuses deliberately remain small to prevent
        double-counting correlated indicators.
        """

        score = 0

        has_payment = cls._has_payment(
            signals,
            evidence,
        )

        has_credentials = cls._has_credentials(
            signals,
            evidence,
        )

        has_url = cls._has_url(
            signals,
            evidence,
        )

        # -----------------------------------------------------
        # Payment + urgency
        # -----------------------------------------------------

        if (
            has_payment
            and "artificial_urgency" in signals
        ):
            score += 8

        # -----------------------------------------------------
        # Credential + urgency
        # -----------------------------------------------------

        if (
            has_credentials
            and "artificial_urgency" in signals
        ):
            score += 8

        # -----------------------------------------------------
        # Credential + payment
        # -----------------------------------------------------

        if (
            has_credentials
            and has_payment
        ):
            score += 8

        # -----------------------------------------------------
        # Suspicious URL + credential
        # -----------------------------------------------------

        if (
            has_url
            and "suspicious_url" in signals
            and has_credentials
        ):
            score += 12

        # -----------------------------------------------------
        # Suspicious URL + urgency
        # -----------------------------------------------------

        if (
            "suspicious_url" in signals
            and "artificial_urgency" in signals
        ):
            score += 6

        # -----------------------------------------------------
        # Impersonation + credential
        # -----------------------------------------------------

        if (
            "impersonation" in signals
            and has_credentials
        ):
            score += 7

        # -----------------------------------------------------
        # Impersonation + payment
        # -----------------------------------------------------

        if (
            "impersonation" in signals
            and has_payment
        ):
            score += 7

        # -----------------------------------------------------
        # Investment + payment
        # -----------------------------------------------------

        if (
            "investment_scam" in signals
            and has_payment
        ):
            score += 5

        # -----------------------------------------------------
        # Job + payment
        # -----------------------------------------------------

        if (
            "job_scam" in signals
            and has_payment
        ):
            score += 5

        # -----------------------------------------------------
        # Prize + payment
        # -----------------------------------------------------

        if (
            "prize_scam" in signals
            and has_payment
        ):
            score += 5

        return score

    # =========================================================
    # Main scoring
    # =========================================================

    @classmethod
    def calculate_risk(
        cls,
        signals: Optional[Iterable[str]],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> RiskResult:
        """
        Calculate Trustiva risk score.
        """

        normalized = cls._normalize_signals(
            signals
        )

        score = 0

        # -----------------------------------------------------
        # Base signal score
        #
        # Contextual labels receive lower weights deliberately.
        # -----------------------------------------------------

        for signal in normalized:

            score += cls.WEIGHTS.get(
                signal,
                0,
            )

        # -----------------------------------------------------
        # Evidence bonuses
        # -----------------------------------------------------

        if evidence:

            if evidence.get("urls"):
                score += cls.EVIDENCE_BONUSES["url"]

            if evidence.get("phone_numbers"):
                score += cls.EVIDENCE_BONUSES["phone"]

            if evidence.get("emails"):
                score += cls.EVIDENCE_BONUSES["email"]

            if evidence.get("money_amounts"):
                score += cls.EVIDENCE_BONUSES["money"]

            if cls._has_credentials(
                normalized,
                evidence,
            ):
                score += cls.EVIDENCE_BONUSES["credential"]

            if evidence.get("organizations"):
                score += cls.EVIDENCE_BONUSES["organization"]

        # -----------------------------------------------------
        # Correlation bonus
        # -----------------------------------------------------

        score += cls._correlation_bonus(
            normalized,
            evidence,
        )

        # -----------------------------------------------------
        # Critical gating
        # -----------------------------------------------------

        critical_reason = cls._critical_reason(
            normalized,
            evidence,
        )

        if critical_reason:

            score = max(
                score,
                cls.CRITICAL_THRESHOLD,
            )

            level = "CRITICAL"

            # Critical scores should still remain bounded.
            score = min(
                score,
                100,
            )

            explanation = (
                f"Critical risk detected ({score}/100). "
                f"{critical_reason}"
            )

            return RiskResult(
                score=score,
                level=level,
                explanation=explanation,
            )

        # -----------------------------------------------------
        # Correlated scam scenarios
        #
        # Prevent ordinary scam narratives from becoming
        # CRITICAL merely because several related labels exist.
        # -----------------------------------------------------

        has_payment = cls._has_payment(
            normalized,
            evidence,
        )

        has_credentials = cls._has_credentials(
            normalized,
            evidence,
        )

        has_url = cls._has_url(
            normalized,
            evidence,
        )

        has_urgency = (
            "artificial_urgency" in normalized
        )

        scam_category = any(
            category in normalized
            for category in [
                "investment_scam",
                "job_scam",
                "prize_scam",
                "social_engineering",
                "phishing",
            ]
        )

        # -----------------------------------------------------
        # Payment + urgency
        # -----------------------------------------------------

        if (
            has_payment
            and has_urgency
            and not has_credentials
            and "suspicious_url" not in normalized
            and "known_threat_indicator" not in normalized
            and "contradicted_claim" not in normalized
        ):
            score = min(
                score,
                70,
            )

        # -----------------------------------------------------
        # Investment/job/prize + payment + urgency
        # -----------------------------------------------------

        if (
            scam_category
            and has_payment
            and has_urgency
            and not has_credentials
            and "suspicious_url" not in normalized
        ):
            score = min(
                score,
                70,
            )

        # -----------------------------------------------------
        # Credential + urgency without strong technical proof
        # -----------------------------------------------------

        if (
            has_credentials
            and has_urgency
            and not has_url
            and "known_threat_indicator" not in normalized
            and "contradicted_claim" not in normalized
        ):
            score = min(
                score,
                70,
            )

        # -----------------------------------------------------
        # Impersonation without strong technical evidence
        # -----------------------------------------------------

        if (
            "impersonation" in normalized
            and "suspicious_url" not in normalized
            and "known_threat_indicator" not in normalized
            and "contradicted_claim" not in normalized
        ):
            score = min(
                score,
                70,
            )

        # -----------------------------------------------------
        # Final classification
        # -----------------------------------------------------

        score = max(
            0,
            min(score, 100),
        )

        if score >= cls.HIGH_THRESHOLD:
            level = "HIGH"

        elif score >= cls.MEDIUM_THRESHOLD:
            level = "MEDIUM"

        else:
            level = "LOW"

        # -----------------------------------------------------
        # Explanation
        # -----------------------------------------------------

        explanation = cls._build_explanation(
            score,
            level,
            normalized,
            evidence,
        )

        return RiskResult(
            score=score,
            level=level,
            explanation=explanation,
        )

    # =========================================================
    # Explanation
    # =========================================================

    @classmethod
    def _build_explanation(
        cls,
        score: int,
        level: str,
        signals: List[str],
        evidence: Optional[Dict[str, Any]],
    ) -> str:

        reasons = []

        if "credential_request" in signals:
            reasons.append(
                "credential or OTP request"
            )

        if "advance_payment" in signals:
            reasons.append(
                "payment or money request"
            )

        if "artificial_urgency" in signals:
            reasons.append(
                "artificial urgency"
            )

        if "suspicious_url" in signals:
            reasons.append(
                "suspicious URL"
            )

        if "impersonation" in signals:
            reasons.append(
                "impersonation indicators"
            )

        if "government_impersonation" in signals:
            reasons.append(
                "government impersonation indicators"
            )

        if "known_threat_indicator" in signals:
            reasons.append(
                "known threat intelligence"
            )

        if "contradicted_claim" in signals:
            reasons.append(
                "contradicted claim"
            )

        if "investment_scam" in signals:
            reasons.append(
                "investment-scam context"
            )

        if "job_scam" in signals:
            reasons.append(
                "job-scam context"
            )

        if "prize_scam" in signals:
            reasons.append(
                "prize-scam context"
            )

        if "phishing" in signals:
            reasons.append(
                "phishing indicators"
            )

        if "social_engineering" in signals:
            reasons.append(
                "social-engineering indicators"
            )

        if not reasons:
            reasons.append(
                "limited risk indicators"
            )

        reason_text = ", ".join(reasons[:5])

        if level == "LOW":

            return (
                f"Low risk detected ({score}/100). "
                f"Only limited risk indicators were identified: "
                f"{reason_text}."
            )

        if level == "MEDIUM":

            return (
                f"Medium risk detected ({score}/100). "
                f"Some risk indicators were identified: "
                f"{reason_text}. "
                f"Independent verification is recommended."
            )

        if level == "HIGH":

            return (
                f"High risk detected ({score}/100). "
                f"Multiple risk indicators were correlated: "
                f"{reason_text}. "
                f"Verify the communication before taking action."
            )

        return (
            f"Critical risk detected ({score}/100). "
            f"Strong independent evidence was detected: "
            f"{reason_text}."
        )


# =============================================================
# Backward-compatible API
# =============================================================

def assess_risk(
    signals: Optional[Iterable[str]],
    evidence: Optional[Dict[str, Any]] = None,
) -> RiskResult:
    """
    Backward-compatible wrapper used by existing tests/modules.
    """

    return RiskEngine.calculate_risk(
        signals,
        evidence,
    )