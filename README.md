# AI-Assisted Phishing Investigation Lab

A small SOC-style tool that investigates a suspicious email: **code finds the red flags and decides the verdict, a local AI explains it, and the human analyst validates it.** It runs fully offline on a laptop using a local model (Ollama + Llama 3.2 3B), so no email data leaves the machine.

> Lab project. All sample emails use fake `.example` domains.

## How it works

```text
Email (.eml)
    -> Parser (sender, reply-to, subject, links, body)
    -> Red-flag checks (domain mismatch, lookalike domain, urgency words, HTTP links)
    -> Verdict + confidence + MITRE ATT&CK decided by code
    -> Local AI writes summary, innocent-explanation check, next steps
    -> Markdown incident report (analyst decision: pending human validation)
```

## What I learned: letting the AI decide the verdict failed

| Version | Design | Result |
|---|---|---|
| 1 | AI judges the email from a basic prompt | Weak: blank finding, low confidence, **invented an ATT&CK ID** (`B1250`) |
| 2 | Code finds red flags, AI gives verdict | Phishing email correct, but **false positive** on a harmless library email (AI invented evidence) |
| 3 | Added prompt rules to stop false positives | Library email correct, but **false negative**: phishing email called "likely legitimate" |
| 4 | **Code decides verdict, AI only explains** | Both sample emails classified correctly |

Takeaway: a small LLM is unreliable as the decision-maker, and tuning the prompt just moved the error around. Moving the verdict into deterministic code, and using the AI for explanation and next steps, fixed it.

## Run it

1. Install Python 3.10+ and [Ollama](https://ollama.com)
2. `ollama pull llama3.2:3b`
3. `pip install ollama`
4. `python parse_email.py sample_phish.eml`
5. `python parse_email.py sample_legit.eml`

Reports are saved to `reports/`.

## Sample output (phishing email)

- Verdict: **Phishing**, High confidence, MITRE ATT&CK **T1566.002** (Spearphishing Link)
- Red flags: sender/reply-to domain mismatch, lookalike domain (`micr0soft`), urgency words, unencrypted HTTP link

## Limitations

- Tested on only 2 sample emails, so this is a proof of concept, not a measured detector
- Red-flag rules are simple and easy to evade
- Does not check domain age or URL reputation yet
- A small local model can still produce weak explanations, so the report is marked "pending human validation"

## Next steps

- Add more test emails and measure true/false positives
- Add domain age and URL reputation lookups
- Check attachments and email authentication headers (SPF/DKIM/DMARC)