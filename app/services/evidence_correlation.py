from typing import Any


class EvidenceCorrelation:
    """
    Correlates multiple Trustiva evidence sources.

    This service does not make a criminal determination.
    It identifies relationships between observable indicators
    and produces an explainable investigation picture.
    """

    # ========================================================
    # CORRELATION RULES
    # ========================================================

    CORRELATION_RULES = [

        {
            "name": "credential_and_payment",
            "required": {
                "credential_request",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "The communication requests sensitive "
                "authentication information while also "
                "requesting money or payment."
            ),
        },

        {
            "name": "urgency_and_credential",
            "required": {
                "urgency",
                "credential_request",
            },
            "severity": "HIGH",
            "explanation": (
                "The communication combines time pressure "
                "with a request for sensitive authentication "
                "information."
            ),
        },

        {
            "name": "urgency_and_payment",
            "required": {
                "urgency",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "The communication combines urgency with "
                "a request for money or payment."
            ),
        },

        {
            "name": "government_and_payment",
            "required": {
                "government_claim",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "A government-related claim is combined "
                "with a request for money or fees."
            ),
        },

        {
            "name": "government_and_credential",
            "required": {
                "government_claim",
                "credential_request",
            },
            "severity": "HIGH",
            "explanation": (
                "A government-related claim is combined "
                "with a request for sensitive authentication "
                "information."
            ),
        },

        {
            "name": "url_and_credential",
            "required": {
                "suspicious_url",
                "credential_request",
            },
            "severity": "HIGH",
            "explanation": (
                "A potentially suspicious URL is combined "
                "with a request for authentication information."
            ),
        },

        {
            "name": "url_and_urgency",
            "required": {
                "suspicious_url",
                "urgency",
            },
            "severity": "MEDIUM",
            "explanation": (
                "A potentially suspicious URL is combined "
                "with time pressure."
            ),
        },

        {
            "name": "impersonation_and_payment",
            "required": {
                "impersonation",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "Possible impersonation is combined with "
                "a financial request."
            ),
        },

        {
            "name": "job_and_payment",
            "required": {
                "job_claim",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "A job-related claim is combined with "
                "a request for fees or payment."
            ),
        },

        {
            "name": "investment_and_payment",
            "required": {
                "investment_claim",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "An investment-related claim is combined "
                "with a financial request."
            ),
        },

        {
            "name": "prize_and_payment",
            "required": {
                "prize_claim",
                "payment_request",
            },
            "severity": "HIGH",
            "explanation": (
                "A prize or reward claim is combined "
                "with a request for payment."
            ),
        },

        {
            "name": "url_and_brand_mismatch",
            "required": {
                "suspicious_url",
                "brand_domain_mismatch",
            },
            "severity": "HIGH",
            "explanation": (
                "A URL mentions a recognizable organization "
                "or brand while the registered domain does "
                "not match the expected domain."
            ),
        },
    ]

    # ========================================================
    # MAIN CORRELATION METHOD
    # ========================================================

    @classmethod
    def correlate(
        cls,
        extracted_evidence: dict[str, Any] | None = None,
        url_results: list[dict[str, Any]] | None = None,
        ai_signals: list[str] | None = None,
        threat_category: str | None = None,
    ) -> dict[str, Any]:

        extracted_evidence = (
            extracted_evidence or {}
        )

        url_results = (
            url_results or []
        )

        ai_signals = (
            ai_signals or []
        )

        # ----------------------------------------------------
        # Build normalized evidence set
        # ----------------------------------------------------

        evidence_signals = cls._build_evidence_signals(
            extracted_evidence,
            url_results,
            ai_signals,
            threat_category,
        )

        # ----------------------------------------------------
        # Apply correlation rules
        # ----------------------------------------------------

        correlations = []

        for rule in cls.CORRELATION_RULES:

            if rule["required"].issubset(
                evidence_signals
            ):

                correlations.append(
                    {
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "explanation": rule["explanation"],
                        "evidence": sorted(
                            rule["required"]
                        ),
                    }
                )

        # ----------------------------------------------------
        # Calculate correlation strength
        # ----------------------------------------------------

        correlation_score = (
            cls._calculate_correlation_score(
                correlations
            )
        )

        correlation_level = (
            cls._correlation_level(
                correlation_score
            )
        )

        # ----------------------------------------------------
        # Generate narrative
        # ----------------------------------------------------

        narrative = (
            cls._generate_narrative(
                correlations,
                evidence_signals,
                correlation_level,
            )
        )

        # ----------------------------------------------------
        # Build evidence relationships
        # ----------------------------------------------------

        relationships = (
            cls._build_relationships(
                extracted_evidence,
                url_results,
                correlations,
            )
        )

        return {
            "evidence_signals": sorted(
                evidence_signals
            ),
            "correlations": correlations,
            "correlation_score": correlation_score,
            "correlation_level": correlation_level,
            "relationships": relationships,
            "narrative": narrative,
        }

    # ========================================================
    # BUILD EVIDENCE SIGNALS
    # ========================================================

    @classmethod
    def _build_evidence_signals(
        cls,
        extracted_evidence: dict[str, Any],
        url_results: list[dict[str, Any]],
        ai_signals: list[str],
        threat_category: str | None,
    ) -> set[str]:

        signals = set()

        # ----------------------------------------------------
        # Extracted evidence
        # ----------------------------------------------------

        requests = [
            str(value).lower()
            for value in extracted_evidence.get(
                "requests",
                [],
            )
        ]

        risk_indicators = [
            str(value).lower()
            for value in extracted_evidence.get(
                "risk_indicators",
                [],
            )
        ]

        categories = [
            str(value).lower()
            for value in extracted_evidence.get(
                "categories",
                [],
            )
        ]

        organizations = (
            extracted_evidence.get(
                "organizations",
                [],
            )
        )

        # ----------------------------------------------------
        # Credential request
        # ----------------------------------------------------

        if any(
            (
                "otp" in value
                or "pin" in value
                or "password" in value
                or "credential" in value
                or "verification code" in value
            )
            for value in requests
        ):

            signals.add(
                "credential_request"
            )

        if (
            "credential_request"
            in risk_indicators
        ):

            signals.add(
                "credential_request"
            )

        # ----------------------------------------------------
        # Payment request
        # ----------------------------------------------------

        if any(
            (
                "payment" in value
                or "money" in value
                or "fee" in value
                or "transfer" in value
            )
            for value in requests
        ):

            signals.add(
                "payment_request"
            )

        if (
            "advance_payment"
            in risk_indicators
        ):

            signals.add(
                "payment_request"
            )

        # ----------------------------------------------------
        # Urgency
        # ----------------------------------------------------

        if (
            "artificial_urgency"
            in risk_indicators
        ):

            signals.add(
                "urgency"
            )

        # ----------------------------------------------------
        # Government
        # ----------------------------------------------------

        if (
            "government_impersonation"
            in categories
        ):

            signals.add(
                "government_claim"
            )

        # ----------------------------------------------------
        # Job
        # ----------------------------------------------------

        if (
            "job_scam"
            in categories
        ):

            signals.add(
                "job_claim"
            )

        # ----------------------------------------------------
        # Investment
        # ----------------------------------------------------

        if (
            "investment_scam"
            in categories
        ):

            signals.add(
                "investment_claim"
            )

        # ----------------------------------------------------
        # Prize
        # ----------------------------------------------------

        if (
            "prize_scam"
            in categories
        ):

            signals.add(
                "prize_claim"
            )

        # ----------------------------------------------------
        # AI signals
        # ----------------------------------------------------

        for signal in ai_signals:

            normalized = (
                str(signal)
                .strip()
                .lower()
                .replace(
                    "-",
                    "_",
                )
                .replace(
                    " ",
                    "_",
                )
            )

            if (
                normalized
                in {
                    "credential_request",
                    "credential_theft",
                    "otp_request",
                    "password_request",
                    "phishing",
                }
            ):

                signals.add(
                    "credential_request"
                )

            if normalized in {
                "advance_payment",
                "payment_request",
                "money_request",
                "verification_fee",
            }:

                signals.add(
                    "payment_request"
                )

            if normalized in {
                "artificial_urgency",
                "urgency",
                "time_pressure",
            }:

                signals.add(
                    "urgency"
                )

            if normalized in {
                "impersonation",
                "government_impersonation",
            }:

                signals.add(
                    "impersonation"
                )

            if normalized == "investment_scam":

                signals.add(
                    "investment_claim"
                )

            if normalized == "job_scam":

                signals.add(
                    "job_claim"
                )

            if normalized == "prize_scam":

                signals.add(
                    "prize_claim"
                )

        # ----------------------------------------------------
        # URL evidence
        # ----------------------------------------------------

        for url_result in url_results:

            indicators = [
                str(value).lower()
                for value in url_result.get(
                    "risk_indicators",
                    [],
                )
            ]

            if indicators:

                signals.add(
                    "suspicious_url"
                )

            if (
                "brand_domain_mismatch"
                in indicators
            ):

                signals.add(
                    "brand_domain_mismatch"
                )

        # ----------------------------------------------------
        # Organization evidence
        # ----------------------------------------------------

        if organizations:

            signals.add(
                "organization_present"
            )

        # ----------------------------------------------------
        # Threat category
        # ----------------------------------------------------

        if threat_category:

            category = (
                threat_category
                .lower()
                .replace(
                    " ",
                    "_",
                )
            )

            if "government" in category:

                signals.add(
                    "government_claim"
                )

            if "job" in category:

                signals.add(
                    "job_claim"
                )

            if "investment" in category:

                signals.add(
                    "investment_claim"
                )

            if "prize" in category:

                signals.add(
                    "prize_claim"
                )

            if (
                "phishing"
                in category
            ):

                signals.add(
                    "credential_request"
                )

        return signals

    # ========================================================
    # CORRELATION SCORE
    # ========================================================

    @staticmethod
    def _calculate_correlation_score(
        correlations: list[dict[str, Any]],
    ) -> int:

        score = 0

        severity_weights = {
            "LOW": 5,
            "MEDIUM": 10,
            "HIGH": 15,
            "CRITICAL": 20,
        }

        for correlation in correlations:

            score += severity_weights.get(
                correlation["severity"],
                0,
            )

        return min(
            score,
            100,
        )

    # ========================================================
    # CORRELATION LEVEL
    # ========================================================

    @staticmethod
    def _correlation_level(
        score: int,
    ) -> str:

        if score >= 45:

            return "STRONG"

        if score >= 25:

            return "MODERATE"

        if score > 0:

            return "WEAK"

        return "NONE"

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    @staticmethod
    def _build_relationships(
        extracted_evidence: dict[str, Any],
        url_results: list[dict[str, Any]],
        correlations: list[dict[str, Any]],
    ) -> list[dict[str, str]]:

        relationships = []

        # ----------------------------------------------------
        # URL relationships
        # ----------------------------------------------------

        for url_result in url_results:

            url = url_result.get(
                "url",
                "",
            )

            hostname = url_result.get(
                "hostname",
                "",
            )

            if hostname:

                relationships.append(
                    {
                        "source": url,
                        "relationship": "resolves_to_host",
                        "target": hostname,
                    }
                )

            for brand in url_result.get(
                "brand_mentions",
                [],
            ):

                relationships.append(
                    {
                        "source": url,
                        "relationship": "mentions_brand",
                        "target": str(brand),
                    }
                )

            for brand in url_result.get(
                "brand_domain_mismatches",
                [],
            ):

                relationships.append(
                    {
                        "source": str(brand),
                        "relationship": "domain_mismatch",
                        "target": hostname,
                    }
                )

        # ----------------------------------------------------
        # Evidence relationships
        # ----------------------------------------------------

        if extracted_evidence.get(
            "phone_numbers"
        ):

            for phone in extracted_evidence[
                "phone_numbers"
            ]:

                relationships.append(
                    {
                        "source": "communication",
                        "relationship": "contains_phone",
                        "target": str(phone),
                    }
                )

        if extracted_evidence.get(
            "money_amounts"
        ):

            for amount in extracted_evidence[
                "money_amounts"
            ]:

                relationships.append(
                    {
                        "source": "communication",
                        "relationship": "requests_or_mentions_amount",
                        "target": str(amount),
                    }
                )

        # ----------------------------------------------------
        # Correlation relationships
        # ----------------------------------------------------

        for correlation in correlations:

            evidence = correlation.get(
                "evidence",
                [],
            )

            if len(evidence) >= 2:

                relationships.append(
                    {
                        "source": evidence[0],
                        "relationship": "correlates_with",
                        "target": evidence[1],
                    }
                )

        return relationships

    # ========================================================
    # NARRATIVE
    # ========================================================

    @staticmethod
    def _generate_narrative(
        correlations: list[dict[str, Any]],
        evidence_signals: set[str],
        correlation_level: str,
    ) -> str:

        if not evidence_signals:

            return (
                "Trustiva did not identify enough "
                "structured evidence to establish "
                "a meaningful correlation."
            )

        if not correlations:

            return (
                "Trustiva identified individual evidence "
                "signals, but no predefined high-confidence "
                "correlation pattern was established. "
                "The available evidence should be evaluated "
                "alongside the AI investigation and trusted "
                "sources."
            )

        explanations = [
            correlation["explanation"]
            for correlation in correlations
        ]

        return (
            "Trustiva identified "
            f"{len(correlations)} correlated evidence "
            f"pattern(s) with {correlation_level.lower()} "
            "correlation strength. "
            + " ".join(
                explanations
            )
        )