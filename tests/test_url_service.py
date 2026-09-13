from app.services.url_service import URLIntelligence


TEST_URLS = [

    # --------------------------------------------------------
    # 1. Brand impersonation example
    # --------------------------------------------------------

    "https://secure-hbl-login.example.com/verify",

    # --------------------------------------------------------
    # 2. IP address URL
    # --------------------------------------------------------

    "http://192.168.1.100/login",

    # --------------------------------------------------------
    # 3. URL shortener
    # --------------------------------------------------------

    "https://bit.ly/3Example",

    # --------------------------------------------------------
    # 4. Normal URL
    # --------------------------------------------------------

    "https://www.hbl.com",

]


print("=" * 80)
print("TRUSTIVA URL INTELLIGENCE TEST")
print("=" * 80)


for number, url in enumerate(
    TEST_URLS,
    start=1,
):

    print("\n")
    print("-" * 80)
    print(f"TEST {number}")
    print("-" * 80)

    print(
        "URL:",
        url,
    )

    result = URLIntelligence.analyze(
        url
    )

    print(
        "Valid:",
        result["valid"],
    )

    print(
        "Hostname:",
        result["hostname"],
    )

    print(
        "Registered Domain:",
        result["registered_domain"],
    )

    print(
        "Scheme:",
        result["scheme"],
    )

    print(
        "HTTPS:",
        result["is_https"],
    )

    print(
        "IP Address:",
        result["is_ip_address"],
    )

    print(
        "URL Shortener:",
        result["is_url_shortener"],
    )

    print(
        "Punycode:",
        result["contains_punycode"],
    )

    print(
        "Subdomains:",
        result["subdomain_count"],
    )

    print(
        "Suspicious Keywords:",
        result["suspicious_keywords"],
    )

    print(
        "Brand Mentions:",
        result["brand_mentions"],
    )

    print(
        "Brand/Domain Mismatch:",
        result["brand_domain_mismatches"],
    )

    print(
        "Risk Indicators:",
        result["risk_indicators"],
    )

    print(
        "Assessment:",
        result["assessment"],
    )


print("\n")
print("=" * 80)
print("URL INTELLIGENCE TEST COMPLETE")
print("=" * 80)