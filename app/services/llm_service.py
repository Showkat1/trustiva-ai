import json
import re
from typing import Any

from openai import OpenAI

from app.config import get_settings
from app.models.analysis import (
    Claim,
    Entity,
    EvidenceReference,
    InvestigationResult,
    RiskSignal,
)
from app.services.rag_service import RAGService


settings = get_settings()


# ============================================================
# LLM CLIENT
# ============================================================

def get_client() -> OpenAI:

    if not settings.llm_api_key:
        raise ValueError(
            "LLM_API_KEY is missing. Add it to the .env file."
        )

    if settings.llm_provider.lower() == "openrouter":

        return OpenAI(
            api_key=settings.llm_api_key,
            base_url="https://openrouter.ai/api/v1",
        )

    return OpenAI(
        api_key=settings.llm_api_key
    )


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are Trustiva AI.

Trustiva AI is a Generative AI-powered digital trust
and fraud intelligence investigation system.

Your job is to investigate suspicious digital
communications using:

1. User-provided evidence
2. Structured evidence extracted from that evidence
3. Retrieved trusted knowledge
4. Evidence-grounded reasoning

You analyze:

- phishing
- fraud
- scams
- social engineering
- impersonation
- government impersonation
- fraudulent job offers
- investment scams
- suspicious payment requests
- credential theft
- suspicious URLs
- artificial urgency
- identity risks

IMPORTANT SAFETY AND REASONING RULES:

1. Never automatically declare a person, phone number,
   organization or account criminal.

2. An unknown sender is NOT automatically fraudulent.

3. Lack of previous reports does NOT prove safety.

4. Extracted evidence represents OBSERVATIONS.
   It does not automatically prove fraud.

5. Retrieved knowledge is supporting evidence,
   not proof that the specific sender is fraudulent.

6. Distinguish clearly between:
   - observed evidence
   - retrieved knowledge
   - claims
   - risk indicators
   - conclusions

7. Never invent external facts.

8. Never fabricate sources.

9. Important claims must indicate whether they require
   independent verification.

10. Use evidence-grounded reasoning.

11. If evidence is insufficient, say so.

12. Do not make definitive criminal accusations.

13. Return ONLY valid JSON.

14. Do NOT use Markdown.

15. Do NOT wrap JSON in code fences.

16. Do NOT add explanations outside the JSON.
"""


# ============================================================
# JSON EXTRACTION
# ============================================================

def extract_json(
    text: str
) -> dict[str, Any]:

    if not text:

        raise ValueError(
            "The AI returned an empty response."
        )

    cleaned = text.strip()

    # Remove Markdown fences if model added them.
    cleaned = re.sub(
        r"^```(?:json)?\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    cleaned = re.sub(
        r"\s*```$",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    cleaned = cleaned.strip()

    # --------------------------------------------------------
    # Attempt 1
    # --------------------------------------------------------

    try:

        parsed = json.loads(
            cleaned
        )

        if isinstance(parsed, dict):
            return parsed

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------------
    # Attempt 2
    # --------------------------------------------------------

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if (
        start != -1
        and end != -1
        and end > start
    ):

        candidate = cleaned[
            start:end + 1
        ]

        try:

            parsed = json.loads(
                candidate
            )

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

    # --------------------------------------------------------
    # Failed
    # --------------------------------------------------------

    raise ValueError(
        "The AI returned invalid JSON.\n\n"
        "AI response preview:\n"
        f"{cleaned[:1500]}"
    )


# ============================================================
# ANALYZE MESSAGE
# ============================================================

def analyze_message(
    text: str,
    rag_service: RAGService,
    extracted_evidence: dict[str, Any] | None = None,
) -> InvestigationResult:

    # ========================================================
    # RAG RETRIEVAL
    # ========================================================

    rag_results = rag_service.search(
        text,
        top_k=4,
    )

    if rag_results:

        evidence_context = "\n\n".join(
            [
                (
                    f"EVIDENCE ID: {index + 1}\n"
                    f"SOURCE: {result['source']}\n"
                    f"TEXT: {result['text']}"
                )
                for index, result in enumerate(
                    rag_results
                )
            ]
        )

    else:

        evidence_context = (
            "No relevant trusted evidence was retrieved."
        )

    # ========================================================
    # STRUCTURED EVIDENCE
    # ========================================================

    if extracted_evidence:

        structured_evidence = json.dumps(
            extracted_evidence,
            ensure_ascii=False,
            indent=2,
        )

    else:

        structured_evidence = (
            "No structured evidence was extracted."
        )

    # ========================================================
    # USER PROMPT
    # ========================================================

    user_prompt = f"""
Investigate the following digital communication.

==================================================
RAW USER EVIDENCE
==================================================

{text}

==================================================
STRUCTURED EXTRACTED EVIDENCE
==================================================

{structured_evidence}

IMPORTANT:

The structured evidence consists of observations
automatically extracted from the user's evidence.

Treat these as evidence signals.

Do NOT assume that an extracted phone number,
URL, organization, amount, or keyword automatically
means fraud.

==================================================
RETRIEVED TRUST KNOWLEDGE
==================================================

{evidence_context}

==================================================
INVESTIGATION REQUIREMENTS
==================================================

Determine:

1. Threat category
2. User intent
3. Important entities
4. Claims requiring verification
5. Risk signals
6. Why each risk signal matters
7. Overall investigation summary
8. Connect claims to relevant retrieved evidence
9. Explain the relationship between observed evidence
   and risk indicators.

==================================================
CLAIM VERIFICATION
==================================================

For every important claim:

Use exactly one:

verified
contradicted
requires_verification
unknown

Provide supporting evidence.

When relevant, reference the retrieved evidence source.

General cybersecurity guidance does NOT prove that
this particular sender is fraudulent.

Use language such as:

"This communication contains indicators consistent with..."

or:

"This claim requires independent verification."

==================================================
JSON OUTPUT
==================================================

Return exactly ONE JSON object.

Use this structure:

{{
    "threat_category": "string",

    "intent": [
        "string"
    ],

    "entities": [
        {{
            "entity_type": "string",
            "value": "string"
        }}
    ],

    "claims": [
        {{
            "claim": "string",
            "verification_status": "requires_verification",
            "supporting_evidence": [
                "string"
            ],
            "evidence_references": [
                {{
                    "source": "string",
                    "excerpt": "string",
                    "relevance": "string"
                }}
            ]
        }}
    ],

    "risk_signals": [
        {{
            "name": "string",
            "severity": "HIGH",
            "explanation": "string"
        }}
    ],

    "summary": "string"
}}
"""

    # ========================================================
    # LLM REQUEST
    # ========================================================

    client = get_client()

    response = client.chat.completions.create(
        model=settings.llm_model,
        temperature=0,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
    )

    content = response.choices[0].message.content

    if not content:

        raise ValueError(
            "The AI returned an empty response."
        )

    # ========================================================
    # DEBUG
    # ========================================================

    print("\n" + "=" * 80)
    print("RAW AI RESPONSE")
    print("=" * 80)
    print(content)
    print("=" * 80 + "\n")

    # ========================================================
    # PARSE JSON
    # ========================================================

    data = extract_json(
        content
    )

    # ========================================================
    # CLAIMS
    # ========================================================

    claims = []

    for claim in data.get(
        "claims",
        [],
    ):

        evidence_references = []

        for reference in claim.get(
            "evidence_references",
            [],
        ):

            evidence_references.append(
                EvidenceReference(
                    source=reference.get(
                        "source",
                        "",
                    ),
                    excerpt=reference.get(
                        "excerpt",
                        "",
                    ),
                    relevance=reference.get(
                        "relevance",
                        "",
                    ),
                )
            )

        claims.append(
            Claim(
                claim=claim.get(
                    "claim",
                    "",
                ),
                verification_status=claim.get(
                    "verification_status",
                    "unknown",
                ),
                supporting_evidence=claim.get(
                    "supporting_evidence",
                    [],
                ),
                evidence_references=evidence_references,
            )
        )

    # ========================================================
    # ENTITIES
    # ========================================================

    entities = []

    for entity in data.get(
        "entities",
        [],
    ):

        entities.append(
            Entity(
                entity_type=entity.get(
                    "entity_type",
                    "",
                ),
                value=entity.get(
                    "value",
                    "",
                ),
            )
        )

    # ========================================================
    # RISK SIGNALS
    # ========================================================

    risk_signals = []

    for signal in data.get(
        "risk_signals",
        [],
    ):

        risk_signals.append(
            RiskSignal(
                name=signal.get(
                    "name",
                    "",
                ),
                severity=signal.get(
                    "severity",
                    "MEDIUM",
                ),
                explanation=signal.get(
                    "explanation",
                    "",
                ),
            )
        )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return InvestigationResult(
        threat_category=data.get(
            "threat_category",
            "Unknown",
        ),
        intent=data.get(
            "intent",
            [],
        ),
        entities=entities,
        claims=claims,
        risk_signals=risk_signals,
        summary=data.get(
            "summary",
            "",
        ),
    )