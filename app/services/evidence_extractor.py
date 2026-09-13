# app/services/evidence_extractor.py

import re
from typing import Dict, List


class EvidenceExtractor:
    """
    Extract structured evidence from suspicious messages.

    Important design principle:
    A negation elsewhere in a message must NOT cancel a genuine request.

    Example:
        "Send PKR 15,000 immediately. If payment is not received..."
    
    The phrase "payment is not received" must not cause the earlier
    "Send PKR 15,000" request to be ignored.
    """

    # ---------------------------------------------------------
    # URL
    # ---------------------------------------------------------

    URL_PATTERN = re.compile(
        r"(https?://[^\s]+|"
        r"www\.[^\s]+|"
        r"\b[a-zA-Z0-9-]+\.(?:com|net|org|pk|gov|edu|co|io|info)"
        r"(?:/[^\s]*)?)",
        re.IGNORECASE,
    )

    # ---------------------------------------------------------
    # Phone numbers
    # ---------------------------------------------------------

    PHONE_PATTERN = re.compile(
        r"(?<!\d)"
        r"(?:\+92[\s-]?\d{3}[\s-]?\d{7}"
        r"|03\d{2}[\s-]?\d{7}"
        r"|0092[\s-]?\d{3}[\s-]?\d{7})"
        r"(?!\d)",
        re.IGNORECASE,
    )

    # ---------------------------------------------------------
    # Email
    # ---------------------------------------------------------

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # ---------------------------------------------------------
    # Money
    # ---------------------------------------------------------

    MONEY_PATTERN = re.compile(
        r"\b(?:PKR|Rs\.?|Rupees?)\s*[\d,]+(?:\.\d+)?"
        r"|\b[\d,]+(?:\.\d+)?\s*(?:PKR|Rs\.?|Rupees?)\b",
        re.IGNORECASE,
    )

    # ---------------------------------------------------------
    # Organizations
    # ---------------------------------------------------------

    ORGANIZATION_PATTERNS = [
        r"\b(?:State Bank of Pakistan|SBP)\b",
        r"\b(?:Federal Board of Revenue|FBR)\b",
        r"\b(?:NADRA)\b",
        r"\b(?:FIA)\b",
        r"\b(?:SECP)\b",
        r"\b(?:National Bank of Pakistan|NBP)\b",
        r"\b(?:HBL|UBL|Meezan Bank|MCB|Bank Alfalah)\b",
        r"\b(?:JazzCash|Easypaisa)\b",
        r"\b(?:Pakistan Government|Government of Pakistan)\b",
        r"\b(?:Amazon|Google|Microsoft|Meta|Apple|WhatsApp)\b",
        r"\b(?:LinkedIn|Indeed|Rozee|Upwork|Fiverr)\b",
    ]

    # ---------------------------------------------------------
    # Credential requests
    # ---------------------------------------------------------

    OTP_PATTERNS = [
        r"\botp\b",
        r"\bone[-\s]?time password\b",
        r"\bverification code\b",
        r"\bsecurity code\b",
        r"\bverification otp\b",
        r"\bcode bhej",
        r"\botp bhej",
        r"\botp share",
        r"\bcode share",
        r"\bcode send",
        r"\botp send",
        r"\bکوڈ\b",
        r"\bاو ٹی پی\b",
    ]

    CREDENTIAL_PATTERNS = [
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\bpin\b",
        r"\bmpin\b",
        r"\busername\b",
        r"\blogin details?\b",
        r"\baccount details?\b",
        r"\bcard details?\b",
        r"\bcredit card\b",
        r"\bdebit card\b",
        r"\bcnic\b",
        r"\bnic\b",
        r"\bidentity card\b",
        r"\bcredentials?\b",
        r"\bپاسورڈ\b",
        r"\bپن\b",
        r"\bشناختی کارڈ\b",
    ]

    # ---------------------------------------------------------
    # Payment / financial requests
    #
    # IMPORTANT:
    # These are evaluated with match-level negation.
    # ---------------------------------------------------------

    FINANCIAL_REQUEST_PATTERNS = [
        r"\bsend\s+(?:pkr|rs\.?|rupees?)\s*[\d,]+",
        r"\bpay\s+(?:pkr|rs\.?|rupees?)\s*[\d,]+",
        r"\binvest\s+(?:pkr|rs\.?|rupees?)\s*[\d,]+",
        r"\btransfer\s+(?:pkr|rs\.?|rupees?)\s*[\d,]+",
        r"\bdeposit\s+(?:pkr|rs\.?|rupees?)\s*[\d,]+",

        r"\b(?:pkr|rs\.?|rupees?)\s*[\d,]+\s+"
        r"(?:registration|processing|verification|security|tax)\s+"
        r"(?:fee|fees|charges?|payment)",

        r"\bpay\s+(?:the\s+)?"
        r"(?:registration|processing|verification|security|tax)\s+"
        r"(?:fee|fees|charges?|payment)",

        r"\bsend\s+money\b",
        r"\bsend\s+funds\b",
        r"\btransfer\s+money\b",
        r"\btransfer\s+funds\b",
        r"\bmake\s+(?:a\s+)?payment\b",
        r"\bpay\s+(?:the\s+)?fee\b",
        r"\bpay\s+(?:the\s+)?charges?\b",
        r"\bdeposit\s+money\b",
        r"\bwire\s+money\b",
    ]

    # ---------------------------------------------------------
    # Generic request language
    # ---------------------------------------------------------

    REQUEST_PATTERNS = [
        r"\bsend\b",
        r"\bshare\b",
        r"\bprovide\b",
        r"\bsubmit\b",
        r"\benter\b",
        r"\bconfirm\b",
        r"\bverify\b",
        r"\bpay\b",
        r"\btransfer\b",
        r"\bdeposit\b",
        r"\binvest\b",
    ]

    # ---------------------------------------------------------
    # Urgency
    # ---------------------------------------------------------

    URGENCY_PATTERNS = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\basap\b",
        r"\bright away\b",
        r"\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b",
        r"\bonly\s+\d+\s*(?:minutes?|hours?)\b",
        r"\blast\s+(?:chance|warning|notice)\b",
        r"\bact\s+now\b",
        r"\bdo\s+not\s+delay\b",
        r"\bdeadline\b",
        r"\bexpire[sd]?\b",
        r"\bexpires?\b",
        r"\bcancelled?\b",
        r"\bterminated?\b",
        r"\bsuspend(?:ed)?\b",
        r"\bفوری\b",
        r"\bجلدی\b",
        r"\bابھی\b",
        r"\bفوراً\b",
    ]

    # ---------------------------------------------------------
    # Scam categories
    # ---------------------------------------------------------

    INVESTMENT_PATTERNS = [
        r"\binvestment\b",
        r"\binvest\b",
        r"\bprofit\b",
        r"\breturns?\b",
        r"\bguaranteed\s+(?:profit|return)\b",
        r"\bdouble\s+your\s+money\b",
        r"\bcrypto\b",
        r"\bforex\b",
        r"\btrading\s+account\b",
        r"\bhigh[-\s]?return\b",
        r"\bguaranteed\s+income\b",
    ]

    JOB_PATTERNS = [
        r"\bjob\b",
        r"\bcareer\b",
        r"\bemployment\b",
        r"\bhiring\b",
        r"\brecruitment\b",
        r"\bvacancy\b",
        r"\bwork\s+from\s+home\b",
        r"\bremote\s+job\b",
        r"\bregistration\s+fee\b",
        r"\bprocessing\s+fee\b",
        r"\bjob\s+offer\b",
    ]

    PRIZE_PATTERNS = [
        r"\bcongratulations\b",
        r"\byou\s+have\s+won\b",
        r"\byou\s+won\b",
        r"\bprize\b",
        r"\blottery\b",
        r"\breward\b",
        r"\bgiveaway\b",
        r"\bjackpot\b",
        r"\bclaim\s+your\s+prize\b",
    ]

    IMPERSONATION_PATTERNS = [
        r"\bofficial\b",
        r"\bgovernment\b",
        r"\bbank\b",
        r"\bsupport\s+team\b",
        r"\bcustomer\s+support\b",
        r"\bsecurity\s+team\b",
        r"\baccount\s+department\b",
        r"\bverification\s+department\b",
        r"\badmin\b",
        r"\badministrator\b",
        r"\bpolice\b",
        r"\bfia\b",
        r"\bnadra\b",
        r"\bfbr\b",
        r"\bstate\s+bank\b",
        r"\bsecp\b",
        r"\bتم\b",
    ]

    # ---------------------------------------------------------
    # Negation
    # ---------------------------------------------------------

    NEGATION_PATTERNS = [
        r"\bnot\b",
        r"\bno\b",
        r"\bnever\b",
        r"\bdo\s+not\b",
        r"\bdon't\b",
        r"\bdoes\s+not\b",
        r"\bdoesn't\b",
        r"\bdid\s+not\b",
        r"\bdidn't\b",
        r"\bwithout\b",
        r"\bnever\s+share\b",
        r"\bdo\s+not\s+share\b",
        r"\bdo\s+not\s+send\b",
        r"\bdo\s+not\s+pay\b",
        r"\bمت\b",
        r"\bنہیں\b",
        r"\bنہ\b",
    ]

    # ---------------------------------------------------------
    # Utility functions
    # ---------------------------------------------------------

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        """Preserve order while removing duplicates."""
        result = []

        for value in values:
            if value not in result:
                result.append(value)

        return result

    @classmethod
    def _contains_any(
        cls,
        text: str,
        patterns: List[str],
    ) -> bool:
        """Return True if any regex pattern matches."""
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return True

        return False

    @classmethod
    def _has_negation_context(
        cls,
        text: str,
        start: int,
        end: int,
        window: int = 45,
    ) -> bool:
        """
        Check whether negation is directly associated with a match.

        We deliberately use a small local window rather than searching
        the entire message.

        This prevents:

            "Send PKR 15,000 immediately.
             If payment is not received..."

        from being incorrectly interpreted as:

            "Do not send PKR 15,000"
        """

        context_start = max(0, start - window)
        context_end = min(len(text), end + window)

        context = text[context_start:context_end]

        # Strong negation immediately before the request.
        before = text[context_start:start]

        strong_before_patterns = [
            r"\bdo\s+not\s*$",
            r"\bdon't\s*$",
            r"\bnever\s*$",
            r"\bdo\s+not\s+(?:send|pay|share|provide|transfer|deposit)\s*$",
            r"\bمت\s*$",
            r"\bنہیں\s*$",
            r"\bنہ\s*$",
        ]

        for pattern in strong_before_patterns:
            if re.search(pattern, before, flags=re.IGNORECASE):
                return True

        # Direct constructions such as:
        # "do not send PKR 5000"
        # "don't pay Rs. 500"
        direct_negation_patterns = [
            r"\bdo\s+not\s+(?:send|pay|transfer|deposit|invest)\b",
            r"\bdon't\s+(?:send|pay|transfer|deposit|invest)\b",
            r"\bnever\s+(?:send|pay|transfer|deposit|invest)\b",
        ]

        for pattern in direct_negation_patterns:
            if re.search(pattern, context, flags=re.IGNORECASE):
                # Make sure the negation is reasonably close to the
                # actual match.
                neg_match = re.search(
                    pattern,
                    context,
                    flags=re.IGNORECASE,
                )

                if neg_match:
                    return True

        # Urdu / Roman Urdu direct negation examples.
        urdu_negation_patterns = [
            r"\bpaise\s+mat\s+(?:bhej|send|do)\b",
            r"\bpaise\s+nahi\s+(?:bhej|send|do)\b",
            r"\botp\s+mat\s+(?:bhej|share|do)\b",
            r"\botp\s+nahi\s+(?:bhej|share|do)\b",
        ]

        for pattern in urdu_negation_patterns:
            if re.search(pattern, context, flags=re.IGNORECASE):
                return True

        return False

    @classmethod
    def _is_actual_request(
        cls,
        text: str,
        match: re.Match,
    ) -> bool:
        """
        Determine whether a matched request is an actual request
        rather than a warning/advisory statement.
        """

        start = match.start()
        end = match.end()

        if cls._has_negation_context(
            text,
            start,
            end,
        ):
            return False

        return True

    # ---------------------------------------------------------
    # Main extraction method
    # ---------------------------------------------------------

    @classmethod
    def extract(cls, text: str) -> Dict:
        """
        Extract structured evidence from text.
        """

        if not text:
            return {
                "urls": [],
                "phone_numbers": [],
                "emails": [],
                "money_amounts": [],
                "organizations": [],
                "requests": [],
                "risk_indicators": [],
                "categories": [],
            }

        original_text = text
        lower_text = text.lower()

        # -----------------------------------------------------
        # Initialize
        # -----------------------------------------------------

        urls: List[str] = []
        phone_numbers: List[str] = []
        emails: List[str] = []
        money_amounts: List[str] = []
        organizations: List[str] = []
        requests: List[str] = []
        risk_indicators: List[str] = []
        categories: List[str] = []

        # -----------------------------------------------------
        # URLs
        # -----------------------------------------------------

        urls = [
            match.group(0).rstrip(".,!?;:)")
            for match in cls.URL_PATTERN.finditer(original_text)
        ]

        urls = cls._unique(urls)

        if urls:
            risk_indicators.append("url_present")

        # -----------------------------------------------------
        # Phone numbers
        # -----------------------------------------------------

        phone_numbers = [
            match.group(0)
            for match in cls.PHONE_PATTERN.finditer(original_text)
        ]

        phone_numbers = cls._unique(phone_numbers)

        # -----------------------------------------------------
        # Emails
        # -----------------------------------------------------

        emails = [
            match.group(0)
            for match in cls.EMAIL_PATTERN.finditer(original_text)
        ]

        emails = cls._unique(emails)

        # -----------------------------------------------------
        # Money
        # -----------------------------------------------------

        money_amounts = [
            match.group(0)
            for match in cls.MONEY_PATTERN.finditer(original_text)
        ]

        money_amounts = cls._unique(money_amounts)

        # -----------------------------------------------------
        # Organizations
        # -----------------------------------------------------

        for pattern in cls.ORGANIZATION_PATTERNS:
            matches = re.findall(
                pattern,
                original_text,
                flags=re.IGNORECASE,
            )

            for item in matches:
                if isinstance(item, tuple):
                    item = next(
                        (part for part in item if part),
                        "",
                    )

                if item and item not in organizations:
                    organizations.append(item)

        # -----------------------------------------------------
        # Credential / OTP requests
        # -----------------------------------------------------

        credential_detected = False

        for pattern in cls.OTP_PATTERNS:
            for match in re.finditer(
                pattern,
                lower_text,
                flags=re.IGNORECASE,
            ):
                if cls._is_actual_request(
                    lower_text,
                    match,
                ):
                    credential_detected = True
                    break

            if credential_detected:
                break

        for pattern in cls.CREDENTIAL_PATTERNS:
            for match in re.finditer(
                pattern,
                lower_text,
                flags=re.IGNORECASE,
            ):
                if cls._is_actual_request(
                    lower_text,
                    match,
                ):
                    credential_detected = True
                    break

            if credential_detected:
                break

        if credential_detected:
            requests.append("OTP / verification code")
            risk_indicators.append("credential_request")

        # -----------------------------------------------------
        # Financial / payment requests
        #
        # THIS IS THE TC09 FIX.
        #
        # We check negation around each individual match instead
        # of checking whether "not" occurs anywhere in the text.
        # -----------------------------------------------------

        payment_detected = False

        for pattern in cls.FINANCIAL_REQUEST_PATTERNS:
            matches = re.finditer(
                pattern,
                lower_text,
                flags=re.IGNORECASE,
            )

            for match in matches:

                if not cls._is_actual_request(
                    lower_text,
                    match,
                ):
                    continue

                payment_detected = True
                break

            if payment_detected:
                break

        if payment_detected:
            requests.append("Payment / money transfer")
            risk_indicators.append("advance_payment")

        # -----------------------------------------------------
        # Generic request detection
        # -----------------------------------------------------

        generic_request_detected = False

        for pattern in cls.REQUEST_PATTERNS:
            for match in re.finditer(
                pattern,
                lower_text,
                flags=re.IGNORECASE,
            ):
                if cls._is_actual_request(
                    lower_text,
                    match,
                ):
                    generic_request_detected = True
                    break

            if generic_request_detected:
                break

        # -----------------------------------------------------
        # Urgency
        # -----------------------------------------------------

        urgency_detected = cls._contains_any(
            lower_text,
            cls.URGENCY_PATTERNS,
        )

        if urgency_detected:
            risk_indicators.append("artificial_urgency")

        # -----------------------------------------------------
        # Investment scam
        # -----------------------------------------------------

        investment_detected = cls._contains_any(
            lower_text,
            cls.INVESTMENT_PATTERNS,
        )

        if investment_detected:
            categories.append("investment_scam")

            # Investment alone should not automatically mean fraud.
            # Stronger signal when money/payment is involved.
            if payment_detected or money_amounts:
                risk_indicators.append("investment_scam")

        # -----------------------------------------------------
        # Job scam
        # -----------------------------------------------------

        job_detected = cls._contains_any(
            lower_text,
            cls.JOB_PATTERNS,
        )

        if job_detected:
            categories.append("job_scam")

            if (
                payment_detected
                or credential_detected
                or urgency_detected
            ):
                risk_indicators.append("job_scam")

        # -----------------------------------------------------
        # Prize scam
        # -----------------------------------------------------

        prize_detected = cls._contains_any(
            lower_text,
            cls.PRIZE_PATTERNS,
        )

        if prize_detected:
            categories.append("prize_scam")

            if payment_detected or money_amounts:
                risk_indicators.append("prize_scam")

        # -----------------------------------------------------
        # Phishing
        # -----------------------------------------------------

        phishing_detected = False

        phishing_patterns = [
            r"\bphishing\b",
            r"\blogin\b",
            r"\bsign\s+in\b",
            r"\bverify\s+your\s+account\b",
            r"\baccount\s+verification\b",
            r"\bclick\s+(?:here|the\s+link)\b",
            r"\bconfirm\s+your\s+account\b",
        ]

        if cls._contains_any(
            lower_text,
            phishing_patterns,
        ):
            phishing_detected = True

        if (
            phishing_detected
            and (
                credential_detected
                or urls
                or urgency_detected
            )
        ):
            risk_indicators.append("phishing")
            categories.append("phishing")

        # -----------------------------------------------------
        # Impersonation
        # -----------------------------------------------------

        impersonation_detected = cls._contains_any(
            lower_text,
            cls.IMPERSONATION_PATTERNS,
        )

        if impersonation_detected:

            # Organization + suspicious behavior is stronger
            # than merely mentioning a bank or government agency.
            if (
                organizations
                or credential_detected
                or payment_detected
                or urls
                or urgency_detected
            ):
                risk_indicators.append("impersonation")
                categories.append("impersonation")

        # -----------------------------------------------------
        # Social engineering
        # -----------------------------------------------------

        if (
            urgency_detected
            and (
                credential_detected
                or payment_detected
            )
        ):
            risk_indicators.append("social_engineering")

        # -----------------------------------------------------
        # Suspicious URL
        #
        # Basic URL-level indicator only.
        # Actual URL reputation can be added later through
        # url_service.py.
        # -----------------------------------------------------

        suspicious_url_terms = [
            "bit.ly",
            "tinyurl",
            "t.co",
            "goo.gl",
            "is.gd",
            "ow.ly",
            "cutt.ly",
            "shorturl",
            "login-",
            "verify-",
            "secure-",
            "account-",
            "update-",
            "claim-",
        ]

        suspicious_url_detected = False

        for url in urls:
            url_lower = url.lower()

            if any(
                term in url_lower
                for term in suspicious_url_terms
            ):
                suspicious_url_detected = True
                break

        if suspicious_url_detected:
            risk_indicators.append("suspicious_url")

        # -----------------------------------------------------
        # Government impersonation
        # -----------------------------------------------------

        government_terms = [
            "government",
            "federal board",
            "fbr",
            "fia",
            "nadra",
            "secp",
            "state bank",
            "sbp",
            "government of pakistan",
        ]

        government_detected = any(
            term in lower_text
            for term in government_terms
        )

        if (
            government_detected
            and (
                impersonation_detected
                or payment_detected
                or credential_detected
                or urgency_detected
            )
        ):
            risk_indicators.append(
                "government_impersonation"
            )

        # -----------------------------------------------------
        # Unverified identity
        # -----------------------------------------------------

        identity_terms = [
            "unknown sender",
            "unverified sender",
            "verify sender",
            "verify identity",
            "unknown number",
            "unverified number",
        ]

        if cls._contains_any(
            lower_text,
            identity_terms,
        ):
            risk_indicators.append(
                "unverified_identity"
            )

        # -----------------------------------------------------
        # Normalize
        # -----------------------------------------------------

        requests = cls._unique(requests)
        risk_indicators = cls._unique(risk_indicators)
        categories = cls._unique(categories)
        organizations = cls._unique(organizations)

        # -----------------------------------------------------
        # Final result
        # -----------------------------------------------------

        return {
            "urls": urls,
            "phone_numbers": phone_numbers,
            "emails": emails,
            "money_amounts": money_amounts,
            "organizations": organizations,
            "requests": requests,
            "risk_indicators": risk_indicators,
            "categories": categories,
        }