import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse


class URLIntelligence:
    """
    Deterministic URL analysis service.

    This service identifies observable URL characteristics.
    It does NOT claim that a URL is malicious based only on
    appearance.
    """

    # ========================================================
    # SUSPICIOUS KEYWORDS
    # ========================================================

    SUSPICIOUS_KEYWORDS = [
        "login",
        "log-in",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "confirm",
        "password",
        "credential",
        "wallet",
        "payment",
        "refund",
        "reward",
        "prize",
        "claim",
        "bonus",
        "otp",
        "kyc",
        "banking",
    ]

    # ========================================================
    # COMMON URL SHORTENERS
    # ========================================================

    URL_SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly",
        "rb.gy",
        "s.id",
    }

    # ========================================================
    # BRAND DOMAINS
    # ========================================================

    KNOWN_BRANDS = {
        "hbl": [
            "hbl.com",
            "hbl.com.pk",
        ],
        "ubl": [
            "ubl.com.pk",
            "ubldigital.com",
        ],
        "mcb": [
            "mcb.com.pk",
        ],
        "meezan": [
            "meezanbank.com",
        ],
        "jazz": [
            "jazz.com.pk",
        ],
        "zong": [
            "zong.com.pk",
        ],
        "telenor": [
            "telenor.com.pk",
        ],
        "ufone": [
            "ufone.com",
        ],
        "nadra": [
            "nadra.gov.pk",
        ],
        "sbp": [
            "sbp.org.pk",
        ],
        "fia": [
            "fia.gov.pk",
        ],
    }

    # ========================================================
    # MAIN ANALYSIS
    # ========================================================

    @classmethod
    def analyze(
        cls,
        url: str,
    ) -> dict:

        original_url = url.strip()

        if not original_url:

            return {
                "url": "",
                "valid": False,
                "error": "Empty URL",
                "hostname": "",
                "registered_domain": "",
                "scheme": "",
                "port": None,
                "is_https": False,
                "is_ip_address": False,
                "is_url_shortener": False,
                "contains_at_symbol": False,
                "contains_punycode": False,
                "subdomain_count": 0,
                "suspicious_keywords": [],
                "query_parameters": [],
                "brand_mentions": [],
                "brand_domain_mismatches": [],
                "risk_indicators": [],
                "assessment": (
                    "No URL was provided for analysis."
                ),
            }

        normalized_url = cls._normalize_url(
            original_url
        )

        try:

            parsed = urlparse(
                normalized_url
            )

        except Exception as error:

            return {
                "url": original_url,
                "valid": False,
                "error": str(error),
                "hostname": "",
                "registered_domain": "",
                "scheme": "",
                "port": None,
                "is_https": False,
                "is_ip_address": False,
                "is_url_shortener": False,
                "contains_at_symbol": (
                    "@" in original_url
                ),
                "contains_punycode": (
                    "xn--" in original_url.lower()
                ),
                "subdomain_count": 0,
                "suspicious_keywords": [],
                "query_parameters": [],
                "brand_mentions": [],
                "brand_domain_mismatches": [],
                "risk_indicators": [],
                "assessment": (
                    "The URL could not be parsed."
                ),
            }

        hostname = (
            parsed.hostname or ""
        ).lower()

        scheme = (
            parsed.scheme or ""
        ).lower()

        # ----------------------------------------------------
        # Basic properties
        # ----------------------------------------------------

        is_https = (
            scheme == "https"
        )

        is_ip_address = (
            cls._is_ip_address(
                hostname
            )
        )

        is_url_shortener = (
            hostname in cls.URL_SHORTENERS
        )

        contains_at_symbol = (
            "@" in parsed.netloc
        )

        contains_punycode = (
            "xn--" in hostname
        )

        port = cls._get_port(
            parsed
        )

        registered_domain = (
            cls._get_registered_domain(
                hostname
            )
        )

        subdomain_count = (
            cls._count_subdomains(
                hostname,
                registered_domain,
            )
        )

        # ----------------------------------------------------
        # Decode URL for keyword analysis
        # ----------------------------------------------------

        decoded_url = unquote(
            original_url
        ).lower()

        suspicious_keywords = (
            cls._find_keywords(
                decoded_url
            )
        )

        # ----------------------------------------------------
        # Query parameters
        # ----------------------------------------------------

        query_parameters = []

        if parsed.query:

            query_parameters = list(
                parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                ).keys()
            )

        # ----------------------------------------------------
        # Brand detection
        # ----------------------------------------------------

        brand_mentions = (
            cls._find_brand_mentions(
                decoded_url
            )
        )

        brand_domain_mismatches = (
            cls._find_brand_domain_mismatches(
                hostname,
                brand_mentions,
            )
        )

        # ----------------------------------------------------
        # Risk indicators
        # ----------------------------------------------------

        risk_indicators = []

        if not is_https:

            risk_indicators.append(
                "unencrypted_http"
            )

        if is_ip_address:

            risk_indicators.append(
                "ip_address_url"
            )

        if is_url_shortener:

            risk_indicators.append(
                "url_shortener"
            )

        if contains_at_symbol:

            risk_indicators.append(
                "at_symbol_obfuscation"
            )

        if contains_punycode:

            risk_indicators.append(
                "punycode_domain"
            )

        if subdomain_count >= 3:

            risk_indicators.append(
                "excessive_subdomains"
            )

        if port is not None and port not in (
            80,
            443,
        ):

            risk_indicators.append(
                "non_standard_port"
            )

        if suspicious_keywords:

            risk_indicators.append(
                "suspicious_url_keywords"
            )

        if len(original_url) > 150:

            risk_indicators.append(
                "unusually_long_url"
            )

        if brand_domain_mismatches:

            risk_indicators.append(
                "brand_domain_mismatch"
            )

        # ----------------------------------------------------
        # Assessment
        # ----------------------------------------------------

        assessment = (
            cls._generate_assessment(
                risk_indicators
            )
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        return {
            "url": original_url,
            "valid": bool(
                hostname
            ),
            "error": "",
            "hostname": hostname,
            "registered_domain": registered_domain,
            "scheme": scheme,
            "port": port,
            "is_https": is_https,
            "is_ip_address": is_ip_address,
            "is_url_shortener": is_url_shortener,
            "contains_at_symbol": contains_at_symbol,
            "contains_punycode": contains_punycode,
            "subdomain_count": subdomain_count,
            "suspicious_keywords": suspicious_keywords,
            "query_parameters": query_parameters,
            "brand_mentions": brand_mentions,
            "brand_domain_mismatches": (
                brand_domain_mismatches
            ),
            "risk_indicators": risk_indicators,
            "assessment": assessment,
        }

    # ========================================================
    # URL NORMALIZATION
    # ========================================================

    @staticmethod
    def _normalize_url(
        url: str,
    ) -> str:

        cleaned = url.strip()

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+\-.]*://",
            cleaned,
        ):

            cleaned = (
                "https://"
                + cleaned
            )

        return cleaned

    # ========================================================
    # IP ADDRESS CHECK
    # ========================================================

    @staticmethod
    def _is_ip_address(
        hostname: str,
    ) -> bool:

        if not hostname:
            return False

        try:

            ipaddress.ip_address(
                hostname
            )

            return True

        except ValueError:

            return False

    # ========================================================
    # PORT
    # ========================================================

    @staticmethod
    def _get_port(
        parsed_url,
    ):

        try:

            return parsed_url.port

        except ValueError:

            return None

    # ========================================================
    # REGISTERED DOMAIN
    # ========================================================

    @staticmethod
    def _get_registered_domain(
        hostname: str,
    ) -> str:

        if not hostname:

            return ""

        parts = hostname.split(".")

        if len(parts) < 2:

            return hostname

        # Basic domain extraction.
        #
        # This intentionally avoids external
        # dependencies. It is not a full public
        # suffix-list implementation.

        common_two_part_suffixes = {
            "com.pk",
            "org.pk",
            "gov.pk",
            "net.pk",
            "co.uk",
            "com.au",
            "co.in",
        }

        last_two = ".".join(
            parts[-2:]
        )

        if last_two in common_two_part_suffixes:

            if len(parts) >= 3:

                return ".".join(
                    parts[-3:]
                )

            return last_two

        return ".".join(
            parts[-2:]
        )

    # ========================================================
    # SUBDOMAIN COUNT
    # ========================================================

    @staticmethod
    def _count_subdomains(
        hostname: str,
        registered_domain: str,
    ) -> int:

        if not hostname:
            return 0

        if not registered_domain:
            return 0

        if hostname == registered_domain:

            return 0

        prefix = hostname[
            : -len(registered_domain)
        ].rstrip(".")

        if not prefix:

            return 0

        return len(
            prefix.split(".")
        )

    # ========================================================
    # KEYWORD DETECTION
    # ========================================================

    @classmethod
    def _find_keywords(
        cls,
        url: str,
    ) -> list[str]:

        found = []

        for keyword in cls.SUSPICIOUS_KEYWORDS:

            if keyword in url:

                found.append(
                    keyword
                )

        return found

    # ========================================================
    # BRAND DETECTION
    # ========================================================

    @classmethod
    def _find_brand_mentions(
        cls,
        url: str,
    ) -> list[str]:

        found = []

        for brand in cls.KNOWN_BRANDS:

            if brand in url:

                found.append(
                    brand
                )

        return found

    # ========================================================
    # BRAND / DOMAIN MISMATCH
    # ========================================================

    @classmethod
    def _find_brand_domain_mismatches(
        cls,
        hostname: str,
        brands: list[str],
    ) -> list[str]:

        mismatches = []

        registered_domain = (
            cls._get_registered_domain(
                hostname
            )
        )

        for brand in brands:

            official_domains = (
                cls.KNOWN_BRANDS.get(
                    brand,
                    [],
                )
            )

            if (
                registered_domain
                and registered_domain not in official_domains
            ):

                mismatches.append(
                    brand
                )

        return mismatches

    # ========================================================
    # ASSESSMENT
    # ========================================================

    @staticmethod
    def _generate_assessment(
        indicators: list[str],
    ) -> str:

        if not indicators:

            return (
                "No predefined suspicious URL "
                "characteristics were detected. "
                "This does not prove that the URL is safe."
            )

        if len(indicators) >= 4:

            return (
                "The URL contains multiple "
                "characteristics associated with "
                "potentially deceptive or risky links. "
                "Independent verification is recommended."
            )

        return (
            "The URL contains one or more "
            "characteristics that warrant "
            "independent verification."
        )