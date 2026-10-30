# Sanctions Screening — Insertion Point & Design

## 1. Pipeline Position

Current pipeline retrieved via `get_compliance_pipeline` (banking-api MCP):

```
kyc_check → aml_analysis → [NEW: sanctions_screening] → approval
```

**Step sequence after insertion:**

| Step | Name | Description |
|------|------|-------------|
| 1 | `kyc_check` | Verify customer identity |
| 2 | `aml_analysis` | Anti-money laundering screening |
| 3 | `sanctions_screening` | Real-time OFAC/UN sanctions list screening *(new)* |
| 4 | `approval` | Final compliance approval |

**Rationale:** Sanctions screening must occur after AML analysis (which confirms the transaction risk profile) but before final approval. The AML step establishes whether a transaction pattern is suspicious; sanctions screening independently checks whether any named counterparty appears on a prohibited list. Both checks must pass before approval. Placing sanctions screening here also means a positive AML flag can be passed as context, but the sanctions check runs on its own deterministic criteria.

## 2. Data Inputs Required

| Field | Type | Source | Notes |
|---|---|---|---|
| `customer_id` | string | banking-api MCP / transaction record | Existing customer record lookup |
| `counterparty_details` | object | Transaction payload | Must include `name`; optionally `country`, `account` |
| `transaction_amount` | float | Transaction payload | Used for risk-weighting, not match logic |

Sample transaction shape (from `get_compliance_pipeline` sample data):

```json
{
  "customer_id": "CUST-00123",
  "counterparty_details": {
    "name": "Acme Trading Ltd",
    "country": "US"
  },
  "transaction_amount": 5000.00
}
```

## 3. Output Schema

```json
{
  "screened": true,
  "match_list": [
    {
      "list_source": "OFAC",
      "matched_name": "Acme Trading Ltd",
      "score": 0.91
    }
  ],
  "confidence": 0.91
}
```

| Field | Type | Description |
|-------|------|-------------|
| `screened` | bool | Whether the screening step executed successfully. `false` if API unreachable or input invalid. |
| `match_list` | list | Zero or more OFAC/UN matches. Each entry has `list_source`, `matched_name`, `score` (0–1). |
| `confidence` | float (0–1) | Maximum match score across all lists; `0.0` if no matches. |

**Hard stop rule:** `match_list` non-empty AND `confidence >= 0.75` triggers a manual compliance review hold — transaction does not proceed to approval automatically.

## 4. Integration Contract with the AML Module

- **Input from AML module:** `aml_result` (status, risk_score) passes through unchanged to the approval step. Sanctions screening runs independently and does not modify the AML verdict.
- **Output to Approval step:** The sanctions screening result is appended to the compliance record. Any non-empty `match_list` with `confidence >= 0.75` is a hard stop.
- **Failure mode:** If the sanctions API is unreachable, `screened` must be `false` and the transaction routed to manual review — it must never silently pass.
- **No plaintext PII in logs:** `customer_id` and counterparty name are masked in log output (PCI DSS Req 3).
- **Encrypted storage:** The screening result is written via an encrypted-storage call site before returning (PCI DSS Req 3/4).

## 5. Open Questions / Risks

- **False-positive rate:** Fuzzy name matching (e.g. Levenshtein distance) may flag legitimate counterparties. Threshold tuning (currently `confidence >= 0.75`) will need ongoing calibration.
- **List refresh cadence:** OFAC/UN lists update on irregular schedules. A stale local cache could miss newly listed entities; the integration should check list age and alert if > 24 h stale.
- **Performance budget:** Response must complete within 200 ms (per compliance SLA). Stub testing validates this; production API integration must be benchmarked.
- **Dual-list precedence:** When a name matches both OFAC and UN lists, the `confidence` field takes the maximum score; both entries appear in `match_list` for audit purposes.
