def generate_response(risk_level_value: str, signals: list[str]):
    if risk_level_value == "CRITICAL":
        return [
            "Do not send money.",
            "Do not share OTP, PIN, password, or identity credentials.",
            "Do not click suspicious links.",
            "Verify the organization through its official website or known contact channel.",
            "If money or sensitive information was already shared, contact the relevant financial institution immediately.",
        ]

    if risk_level_value == "HIGH":
        return [
            "Do not provide sensitive information yet.",
            "Verify the sender independently.",
            "Check links and organization details before taking action.",
        ]

    if risk_level_value == "MEDIUM":
        return [
            "Treat the communication with caution.",
            "Verify important claims through trusted sources.",
        ]

    return [
        "No major risk indicators were detected.",
        "Continue to verify important claims independently.",
    ]