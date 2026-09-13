import io

import fitz
import streamlit as st

from app.services.llm_service import analyze_message
from app.services.rag_service import RAGService
from app.services.risk_engine import assess_risk
from app.services.response_service import generate_response
from app.services.ocr_service import OCRService
from app.services.evidence_extractor import EvidenceExtractor
from app.services.url_service import URLIntelligence
from app.services.evidence_correlation import EvidenceCorrelation


# ============================================================
# DOCUMENT EXTRACTION
# ============================================================

def extract_document_text(uploaded_file) -> str:
    """Extract readable text from a PDF or plain-text upload."""
    name = (uploaded_file.name or "").lower()
    data = uploaded_file.getvalue()

    if name.endswith(".txt"):
        return data.decode("utf-8", errors="ignore").strip()

    if name.endswith(".pdf"):
        document = fitz.open(stream=data, filetype="pdf")
        try:
            pages = [page.get_text("text") for page in document]
            return "\n\n".join(pages).strip()
        finally:
            document.close()

    raise ValueError("Unsupported document type. Please upload a PDF or TXT file.")


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Trustiva AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main {
        padding-top: 1rem;
    }

    .trustiva-header {
        padding: 1.5rem 0 0.5rem 0;
    }

    .trustiva-title {
        font-size: 2.6rem;
        font-weight: 800;
        margin-bottom: 0;
    }

    .trustiva-tagline {
        font-size: 1.15rem;
        color: #666;
        margin-top: 0.2rem;
    }

    .section-title {
        font-size: 1.45rem;
        font-weight: 700;
        margin-top: 1.5rem;
        margin-bottom: 0.7rem;
    }

    .metric-card {
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(128,128,128,0.25);
        text-align: center;
        min-height: 115px;
    }

    .metric-label {
        font-size: 0.85rem;
        color: #777;
    }

    .metric-value {
        font-size: 1.65rem;
        font-weight: 750;
        margin-top: 0.3rem;
    }

    .evidence-card {
        padding: 0.8rem;
        border-radius: 10px;
        border: 1px solid rgba(128,128,128,0.20);
        margin-bottom: 0.5rem;
    }

    .pipeline-step {
        padding: 0.7rem;
        text-align: center;
        border-radius: 10px;
        border: 1px solid rgba(128,128,128,0.20);
        font-size: 0.85rem;
        min-height: 70px;
    }

    .report-box {
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(128,128,128,0.25);
        margin-bottom: 1rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# RAG SERVICE
# ============================================================

@st.cache_resource
def get_rag_service():
    return RAGService()


rag_service = get_rag_service()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="trustiva-header">
        <div class="trustiva-title">🛡️ Trustiva AI</div>
        <div class="trustiva-tagline">
            Verify Before You Trust.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.caption(
    "Generative AI Digital Trust & Fraud Intelligence Platform"
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ Trustiva AI")

    st.markdown(
        """
        **Digital Trust Investigation**

        Trustiva analyzes suspicious digital
        communications and correlates evidence
        before providing a risk assessment.
        """
    )

    st.divider()

    st.markdown("### Investigation Pipeline")

    st.markdown(
        """
        1. 📥 Evidence Intake
        2. 🔎 Evidence Extraction
        3. 🔗 URL Intelligence
        4. 🧠 AI Investigation
        5. 📚 RAG Verification
        6. 🕸️ Evidence Correlation
        7. 📊 Risk Assessment
        8. 🛡️ Protection
        """
    )

    st.divider()

    st.caption(
        "Trustiva provides risk intelligence and "
        "does not make definitive criminal accusations."
    )


# ============================================================
# INPUT SECTION
# ============================================================

st.markdown(
    '<div class="section-title">🔍 Analyze Digital Evidence</div>',
    unsafe_allow_html=True,
)

st.caption(
    "Investigate suspicious messages, URLs, screenshots, or documents using GenAI, RAG, and evidence correlation."
)

input_mode = st.radio(
    "Evidence source",
    [
        "📝 Message",
        "🔗 URL",
        "📸 Screenshot",
        "📄 Document",
    ],
    horizontal=True,
)

message = ""
uploaded_image = None
uploaded_document = None

if input_mode == "📝 Message":
    message = st.text_area(
        "Paste suspicious content",
        height=220,
        placeholder=(
            "Example:\n\n"
            "Your bank account will be suspended immediately. "
            "Click https://secure-bank-login.com and enter your OTP "
            "and password to restore access."
        ),
        label_visibility="visible",
    )

elif input_mode == "🔗 URL":
    url_input = st.text_input(
        "Suspicious URL",
        placeholder="https://example.com/verify-account",
    )
    if url_input.strip():
        message = f"Please investigate this URL for digital trust and fraud risk: {url_input.strip()}"

elif input_mode == "📸 Screenshot":
    uploaded_image = st.file_uploader(
        "Upload a screenshot",
        type=["png", "jpg", "jpeg"],
        help="Upload an SMS, WhatsApp, email, social-media message, or other suspicious communication.",
    )
    if uploaded_image:
        st.image(uploaded_image, caption="Uploaded Evidence", use_container_width=True)

else:
    uploaded_document = st.file_uploader(
        "Upload a document",
        type=["pdf", "txt"],
        help="Upload a suspicious PDF or text document for investigation.",
    )

if input_mode in {"📝 Message", "🔗 URL"} and message.strip():
    if input_mode == "📝 Message":
        st.caption(f"{len(message.strip())} characters ready for investigation")


# ============================================================
# INVESTIGATE
# ============================================================

if st.button(
    "🔎 Investigate with Trustiva AI",
    type="primary",
    use_container_width=True,
):

    # ========================================================
    # PREPARE TEXT
    # ========================================================

    # Prepare text from the selected evidence source.
    if input_mode == "📝 Message":
        if not message.strip():
            st.warning("Please provide a message to investigate.")
            st.stop()

    elif input_mode == "🔗 URL":
        if not message.strip():
            st.warning("Please provide a URL to investigate.")
            st.stop()

    elif input_mode == "📸 Screenshot":
        if uploaded_image is None:
            st.warning("Please upload a screenshot first.")
            st.stop()
        try:
            with st.spinner("Reading screenshot with OCR..."):
                message = OCRService.extract_text(uploaded_image)
        except Exception as error:
            st.error(f"OCR failed: {error}")
            st.stop()
        if not message.strip():
            st.error("No readable text was extracted from the screenshot.")
            st.stop()
        with st.expander("📝 View OCR-extracted evidence", expanded=True):
            st.text_area("Extracted text", value=message, height=180, disabled=True)

    else:
        if uploaded_document is None:
            st.warning("Please upload a PDF or TXT document first.")
            st.stop()
        try:
            with st.spinner("Extracting document text..."):
                message = extract_document_text(uploaded_document)
        except Exception as error:
            st.error(f"Document extraction failed: {error}")
            st.stop()
        if not message.strip():
            st.error("No readable text was extracted from the document.")
            st.stop()
        with st.expander("📄 View extracted document evidence", expanded=True):
            st.text_area("Extracted text", value=message, height=220, disabled=True)

    # ========================================================
    # EVIDENCE EXTRACTION
    # ========================================================

    with st.spinner(
        "Extracting structured evidence..."
    ):

        try:

            extracted_evidence = (
                EvidenceExtractor.extract(
                    message
                )
            )

        except Exception as error:

            st.error(
                f"Evidence extraction failed: {error}"
            )

            st.stop()

    # ========================================================
    # URL INTELLIGENCE
    # ========================================================

    url_results = []

    if extracted_evidence["urls"]:

        with st.spinner(
            "Analyzing detected URLs..."
        ):

            for url in extracted_evidence["urls"]:

                try:

                    result = URLIntelligence.analyze(
                        url
                    )

                    url_results.append(
                        result
                    )

                except Exception as error:

                    url_results.append(
                        {
                            "url": url,
                            "valid": False,
                            "error": str(error),
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
                                "URL analysis failed."
                            ),
                        }
                    )

    # ========================================================
    # EXECUTIVE REPORT HEADER
    # ========================================================

    st.divider()

    st.markdown(
        "## 📋 Trustiva Investigation Report"
    )

    st.caption(
        "AI-generated investigation based on supplied "
        "evidence, retrieved knowledge, and deterministic "
        "evidence analysis."
    )

    # ========================================================
    # EVIDENCE OVERVIEW
    # ========================================================

    st.markdown(
        '<div class="section-title">📊 Evidence Overview</div>',
        unsafe_allow_html=True,
    )

    evidence_counts = [
        (
            "🔗 URLs",
            len(extracted_evidence["urls"]),
        ),
        (
            "📱 Phones",
            len(extracted_evidence["phone_numbers"]),
        ),
        (
            "📧 Emails",
            len(extracted_evidence["emails"]),
        ),
        (
            "💰 Amounts",
            len(extracted_evidence["money_amounts"]),
        ),
        (
            "🏢 Organizations",
            len(extracted_evidence["organizations"]),
        ),
        (
            "⚠️ Indicators",
            len(extracted_evidence["risk_indicators"]),
        ),
    ]

    columns = st.columns(6)

    for column, (label, value) in zip(
        columns,
        evidence_counts,
    ):

        with column:

            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ========================================================
    # DETECTED EVIDENCE DETAILS
    # ========================================================

    with st.expander(
        "🔎 View Extracted Evidence",
        expanded=True,
    ):

        left, right = st.columns(2)

        with left:

            st.markdown("**🔗 URLs**")

            if extracted_evidence["urls"]:

                for value in extracted_evidence["urls"]:

                    st.code(value)

            else:

                st.caption("None detected.")

            st.markdown("**📱 Phone Numbers**")

            if extracted_evidence["phone_numbers"]:

                for value in extracted_evidence[
                    "phone_numbers"
                ]:

                    st.write(f"• {value}")

            else:

                st.caption("None detected.")

            st.markdown("**📧 Emails**")

            if extracted_evidence["emails"]:

                for value in extracted_evidence[
                    "emails"
                ]:

                    st.write(f"• {value}")

            else:

                st.caption("None detected.")

        with right:

            st.markdown("**💰 Money Amounts**")

            if extracted_evidence["money_amounts"]:

                for value in extracted_evidence[
                    "money_amounts"
                ]:

                    st.write(f"• {value}")

            else:

                st.caption("None detected.")

            st.markdown("**🏢 Organizations**")

            if extracted_evidence["organizations"]:

                for value in extracted_evidence[
                    "organizations"
                ]:

                    st.write(f"• {value}")

            else:

                st.caption("None detected.")

            st.markdown(
                "**🔐 Requested Information / Actions**"
            )

            if extracted_evidence["requests"]:

                for value in extracted_evidence[
                    "requests"
                ]:

                    st.write(f"• {value}")

            else:

                st.caption("None detected.")

    # ========================================================
    # URL INTELLIGENCE
    # ========================================================

    if url_results:

        st.markdown(
            '<div class="section-title">🔗 URL Intelligence</div>',
            unsafe_allow_html=True,
        )

        for url_result in url_results:

            with st.expander(
                f"🔗 {url_result['url']}",
                expanded=True,
            ):

                c1, c2, c3, c4 = st.columns(4)

                with c1:

                    st.metric(
                        "HTTPS",
                        "Yes"
                        if url_result["is_https"]
                        else "No",
                    )

                with c2:

                    st.metric(
                        "IP URL",
                        "Yes"
                        if url_result["is_ip_address"]
                        else "No",
                    )

                with c3:

                    st.metric(
                        "Shortener",
                        "Yes"
                        if url_result[
                            "is_url_shortener"
                        ]
                        else "No",
                    )

                with c4:

                    st.metric(
                        "Subdomains",
                        url_result[
                            "subdomain_count"
                        ],
                    )

                st.markdown(
                    "**Hostname**"
                )

                st.code(
                    url_result["hostname"]
                    or "Unavailable"
                )

                st.markdown(
                    "**Registered Domain**"
                )

                st.code(
                    url_result[
                        "registered_domain"
                    ]
                    or "Unavailable"
                )

                if url_result[
                    "suspicious_keywords"
                ]:

                    st.markdown(
                        "**⚠️ Suspicious URL Characteristics**"
                    )

                    for keyword in (
                        url_result[
                            "suspicious_keywords"
                        ]
                    ):

                        st.write(
                            f"• `{keyword}`"
                        )

                if url_result[
                    "brand_domain_mismatches"
                ]:

                    st.warning(
                        "Potential brand/domain mismatch detected."
                    )

                    for brand in (
                        url_result[
                            "brand_domain_mismatches"
                        ]
                    ):

                        st.write(
                            f"Claimed brand: **{brand.upper()}**"
                        )

                if url_result[
                    "risk_indicators"
                ]:

                    st.markdown(
                        "**🚨 URL Risk Indicators**"
                    )

                    for indicator in (
                        url_result[
                            "risk_indicators"
                        ]
                    ):

                        st.write(
                            "• "
                            + indicator.replace(
                                "_",
                                " ",
                            ).title()
                        )

                st.info(
                    url_result["assessment"]
                )

    # ========================================================
    # INVESTIGATION PIPELINE
    # ========================================================

    st.markdown(
        '<div class="section-title">⚙️ Investigation Pipeline</div>',
        unsafe_allow_html=True,
    )

    pipeline = [
        "📥 Evidence\nIntake",
        "🔎 Evidence\nExtraction",
        "🔗 URL\nIntelligence",
        "🧠 AI\nInvestigation",
        "📚 RAG\nVerification",
        "🕸️ Evidence\nCorrelation",
        "📊 Risk\nAssessment",
        "🛡️ Protection",
    ]

    pipeline_columns = st.columns(8)

    for column, step in zip(
        pipeline_columns,
        pipeline,
    ):

        with column:

            st.markdown(
                f"""
                <div class="pipeline-step">
                    {step.replace(chr(10), "<br>")}
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ========================================================
    # AI INVESTIGATION
    # ========================================================

    try:

        with st.spinner(
            "Trustiva AI is investigating the evidence..."
        ):

            investigation = analyze_message(
                message,
                rag_service,
                extracted_evidence,
            )

            # ------------------------------------------------
            # AI SIGNALS
            # ------------------------------------------------

            signal_names = [
                signal.name
                for signal in investigation.risk_signals
            ]

            # ------------------------------------------------
            # URL SIGNALS
            # ------------------------------------------------

            for url_result in url_results:

                for indicator in (
                    url_result[
                        "risk_indicators"
                    ]
                ):

                    if indicator in {
                        "suspicious_url_keywords",
                        "brand_domain_mismatch",
                        "ip_address_url",
                        "url_shortener",
                        "at_symbol_obfuscation",
                        "punycode_domain",
                        "excessive_subdomains",
                        "non_standard_port",
                        "unusually_long_url",
                        "unencrypted_http",
                    }:

                        signal_names.append(
                            "suspicious_url"
                        )

            # ------------------------------------------------
            # CORRELATION
            # ------------------------------------------------

            correlation_result = (
                EvidenceCorrelation.correlate(
                    extracted_evidence=(
                        extracted_evidence
                    ),
                    url_results=url_results,
                    ai_signals=signal_names,
                    threat_category=(
                        investigation.threat_category
                    ),
                )
            )

            # ------------------------------------------------
            # RISK
            # ------------------------------------------------

            risk_result = assess_risk(
                signal_names,
                extracted_evidence,
            )

            # ------------------------------------------------
            # ACTIONS
            # ------------------------------------------------

            actions = generate_response(
                risk_result.level,
                signal_names,
            )

            # ------------------------------------------------
            # RAG
            # ------------------------------------------------

            rag_results = rag_service.search(
                message,
                top_k=4,
            )

    except Exception as error:

        st.error(
            f"Investigation failed: {error}"
        )

        st.stop()

    # ========================================================
    # EXECUTIVE RISK DASHBOARD
    # ========================================================

    st.markdown(
        '<div class="section-title">🛡️ Executive Risk Assessment</div>',
        unsafe_allow_html=True,
    )

    risk_col1, risk_col2, risk_col3, risk_col4 = (
        st.columns(4)
    )

    with risk_col1:

        st.metric(
            "Risk Score",
            f"{risk_result.score}/100",
        )

    with risk_col2:

        st.metric(
            "Risk Level",
            risk_result.level,
        )

    with risk_col3:

        st.metric(
            "Threat Category",
            investigation.threat_category,
        )

    with risk_col4:

        st.metric(
            "Correlation",
            correlation_result[
                "correlation_level"
            ],
        )

    # ========================================================
    # WHY SCORE
    # ========================================================

    st.markdown(
        "### 🧠 Why This Risk Score?"
    )

    st.info(
        risk_result.explanation
    )

    # ========================================================
    # AI SUMMARY
    # ========================================================

    st.markdown(
        "### 🧠 AI Investigation Summary"
    )

    st.markdown(
        f"""
        <div class="report-box">
            {investigation.summary}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ========================================================
    # EVIDENCE CORRELATION
    # ========================================================

    st.markdown(
        '<div class="section-title">🕸️ Evidence Correlation</div>',
        unsafe_allow_html=True,
    )

    corr_col1, corr_col2 = st.columns(2)

    with corr_col1:

        st.metric(
            "Correlation Strength",
            correlation_result[
                "correlation_level"
            ],
        )

    with corr_col2:

        st.metric(
            "Correlation Score",
            f"{correlation_result['correlation_score']}/100",
        )

    st.info(
        correlation_result[
            "narrative"
        ]
    )

    # ========================================================
    # CORRELATED PATTERNS
    # ========================================================

    if correlation_result[
        "correlations"
    ]:

        st.markdown(
            "### 🔗 Correlated Evidence Patterns"
        )

        for correlation in (
            correlation_result[
                "correlations"
            ]
        ):

            name = (
                correlation["name"]
                .replace(
                    "_",
                    " ",
                )
                .title()
            )

            severity = correlation[
                "severity"
            ]

            with st.expander(
                f"{severity} — {name}",
                expanded=True,
            ):

                st.write(
                    correlation[
                        "explanation"
                    ]
                )

                st.markdown(
                    "**Evidence involved:**"
                )

                for evidence in (
                    correlation[
                        "evidence"
                    ]
                ):

                    st.write(
                        "• "
                        + evidence.replace(
                            "_",
                            " ",
                        ).title()
                    )

    # ========================================================
    # EVIDENCE RELATIONSHIPS
    # ========================================================

    if correlation_result[
        "relationships"
    ]:

        st.markdown(
            "### 🕸️ Evidence Relationships"
        )

        relationship_rows = []

        for relationship in (
            correlation_result[
                "relationships"
            ]
        ):

            relationship_rows.append(
                {
                    "Source": relationship[
                        "source"
                    ],
                    "Relationship": (
                        relationship[
                            "relationship"
                        ]
                        .replace(
                            "_",
                            " ",
                        )
                        .title()
                    ),
                    "Target": relationship[
                        "target"
                    ],
                }
            )

        st.dataframe(
            relationship_rows,
            use_container_width=True,
            hide_index=True,
        )

    # ========================================================
    # INTENT
    # ========================================================

    if investigation.intent:

        st.markdown(
            "### 🎯 Detected Intent"
        )

        intent_columns = st.columns(
            min(
                len(investigation.intent),
                3,
            )
        )

        for column, intent in zip(
            intent_columns,
            investigation.intent,
        ):

            with column:

                st.info(
                    intent
                )

    # ========================================================
    # ENTITIES
    # ========================================================

    if investigation.entities:

        st.markdown(
            "### 🔎 Identified Entities"
        )

        entity_rows = []

        for entity in investigation.entities:

            entity_rows.append(
                {
                    "Type": entity.entity_type,
                    "Value": entity.value,
                }
            )

        st.dataframe(
            entity_rows,
            use_container_width=True,
            hide_index=True,
        )

    # ========================================================
    # CLAIM VERIFICATION
    # ========================================================

    if investigation.claims:

        st.markdown(
            "### 📌 Claim Verification"
        )

        for claim in investigation.claims:

            status = (
                claim.verification_status
                .replace(
                    "_",
                    " ",
                )
                .upper()
            )

            with st.expander(
                f"📌 {claim.claim}",
                expanded=False,
            ):

                st.write(
                    f"**Status:** {status}"
                )

                if claim.supporting_evidence:

                    st.markdown(
                        "**Supporting observations:**"
                    )

                    for evidence in (
                        claim.supporting_evidence
                    ):

                        st.write(
                            f"• {evidence}"
                        )

                if claim.evidence_references:

                    st.markdown(
                        "**Retrieved evidence:**"
                    )

                    for reference in (
                        claim.evidence_references
                    ):

                        st.markdown(
                            f"**Source:** "
                            f"{reference.source}"
                        )

                        st.write(
                            reference.excerpt
                        )

                        st.caption(
                            "Relevance: "
                            f"{reference.relevance}"
                        )

    # ========================================================
    # RISK SIGNALS
    # ========================================================

    st.markdown(
        "### 🚨 Risk Signals"
    )

    if investigation.risk_signals:

        signal_rows = []

        for signal in (
            investigation.risk_signals
        ):

            signal_rows.append(
                {
                    "Severity": signal.severity,
                    "Signal": signal.name,
                    "Explanation": signal.explanation,
                }
            )

        st.dataframe(
            signal_rows,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.success(
            "No significant predefined risk signals "
            "were identified."
        )

    # ========================================================
    # PROTECTION CENTER
    # ========================================================

    st.markdown(
        '<div class="section-title">🛡️ Protection & Response Center</div>',
        unsafe_allow_html=True,
    )

    if risk_result.level in {
        "CRITICAL",
        "HIGH",
    }:

        st.warning(
            "Trustiva identified elevated risk indicators. "
            "Review the recommended actions before taking "
            "any further action."
        )

    for index, action in enumerate(
        actions,
        start=1,
    ):

        st.write(
            f"**{index}.** {action}"
        )

    # ========================================================
    # RAG EVIDENCE
    # ========================================================

    st.markdown(
        '<div class="section-title">📚 Trusted Knowledge Used</div>',
        unsafe_allow_html=True,
    )

    if rag_results:

        for index, result in enumerate(
            rag_results,
            start=1,
        ):

            with st.expander(
                f"Evidence Source {index} — "
                f"{result['source']}"
            ):

                st.write(
                    result["text"]
                )

                st.caption(
                    "Semantic retrieval distance: "
                    f"{result['distance']:.4f}"
                )

    else:

        st.info(
            "No relevant trusted knowledge was retrieved."
        )

    # ========================================================
    # FINAL DECISION
    # ========================================================

    st.divider()

    st.markdown(
        "## 🛡️ Trustiva Decision"
    )

    if risk_result.level == "CRITICAL":

        st.error(
            "CRITICAL RISK — Do not proceed without "
            "independent verification."
        )

    elif risk_result.level == "HIGH":

        st.error(
            "HIGH RISK — Strong caution and independent "
            "verification are recommended."
        )

    elif risk_result.level == "MEDIUM":

        st.warning(
            "MEDIUM RISK — Verify important claims "
            "through trusted channels."
        )

    else:

        st.success(
            "LOWER RISK — No major predefined indicators "
            "were identified, but independent verification "
            "is still recommended."
        )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    st.divider()

    st.caption(
        "Trustiva AI provides evidence-based risk intelligence. "
        "Its assessment is not definitive proof that a person, "
        "organization, phone number, URL, or account is fraudulent "
        "or criminal."
    )