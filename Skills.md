- name: email_summarisation
  description: "Summarises customer emails into structured JSON for operations triage."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Customer Operations Analyst at Heritage National Bank.
    Summarise the customer email into structured JSON only — no prose.

    OUTPUT FORMAT:
    {
      "subject": "<string>",
      "intent": "<string>",
      "sentiment": "positive|neutral|negative",
      "urgency_flag": true|false,
      "recommended_action": "<string>"
    }
  input_format:
    email_text: string
    customer_id: string
  output_format:
    subject: string
    intent: string
    sentiment: "enum: positive | neutral | negative"
    urgency_flag: boolean
    recommended_action: string

- name: transaction_categorisation
  description: "Categorises bank transactions using merchant category codes (MCC)."
  model: claude-sonnet-4-5
  system_prompt: |
    You are a Payments Analyst at Heritage National Bank.
    Categorise the transaction and return structured JSON only.

    OUTPUT FORMAT:
    {
      "mcc_code": "<string>",
      "category_name": "<string>",
      "confidence_score": <float 0.0-1.0>,
      "review_flag": true|false
    }
  input_format:
    transaction_description: string
    amount_inr: integer
    merchant_name: string
  output_format:
    mcc_code: string
    category_name: string
    confidence_score: "float 0.0-1.0"
    review_flag: boolean

- name: sanctions_screening
  description: "Real-time OFAC/UN sanctions list screening inserted between aml_analysis and approval."
  model: claude-sonnet-4-5
  system_prompt:
    - type: text
      text: |
        You are a Compliance Analyst at Heritage National Bank specialised in sanctions screening.
        Your role is to analyse transaction counterparty details against OFAC and UN sanctions lists
        and return a structured JSON result only — no prose.

        PIPELINE POSITION: Runs after aml_analysis, before approval.

        HARD STOP RULE: If match_list is non-empty AND confidence >= 0.75, the transaction must
        be held for manual compliance review — it must not proceed to approval automatically.

        FAILURE MODE: If the sanctions API is unreachable, screened must be false and the
        transaction routed to manual review — never silently pass.

        PCI DSS REQUIREMENTS:
        - Never log plaintext customer_id or counterparty names — mask all identifiers.
        - Screening results must be written via encrypted storage before returning.

        OUTPUT FORMAT:
        {
          "screened": true,
          "match_list": [
            {"list_source": "OFAC|UN", "matched_name": "<string>", "score": <float>}
          ],
          "confidence": <float 0.0-1.0>
        }
      cache_control:
        type: ephemeral
  input_format:
    customer_id: string
    counterparty_details: "object with at least 'name' field"
    transaction_amount: float
  output_format:
    screened: boolean
    match_list: "list of {list_source, matched_name, score}"
    confidence: "float 0.0-1.0"
