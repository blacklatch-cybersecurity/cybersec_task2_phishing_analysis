# Phishing Email Analysis Report (Task 2)

**WARNING**: These are synthetic phishing samples for learning only. Do NOT send to real users.

## Sample Email
**Subject:** URGENT: Verify Your Account Now
**Sender (display):** PayHelp Support <security@paypa1.example.com>
**Recipient:** victim@example.com

## Threat Indicators (Based on Internship Guidelines)

| # | Indicator | Evidence in Sample |
|---|------------|-------------------|
| 1 | Spoofed sender address | security@paypa1.example.com pretending to be PayPal |
| 2 | Header anomalies | SPF fail, DKIM none, DMARC fail |
| 3 | Suspicious link | Visible: PayPal, actual: http://example.com/verify |
| 4 | Urgent tone | “Verify your account within 24 hours or suspension” |
| 5 | Grammar issues | “We must verify your identity immediately.” (awkward phrasing) |
| 6 | Generic greeting | “Hello Customer” instead of name |
| 7 | Social engineering | Uses fear of account lockout |
| 8 | Mismatched URLs | Hover link shows different domain |

## Summary
This is a synthetic phishing sample designed for offline analysis. It mimics common phishing traits:
- Spoofed domain (paypa1.example.com looks like paypal)
- Urgent language to create panic
- Link that points to a non-matching domain (http://example.com/verify)
- Missing DKIM and failing SPF in synthetic header

## Recommendations
- Report the email to security team.
- Block sender domain and IP.
- Train users to check sender addresses and avoid urgent link prompts.
- Preserve headers for forensic review.

--
📤 Submitted by: Bala Muruga
