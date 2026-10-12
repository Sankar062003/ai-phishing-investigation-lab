import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import ollama

# Open the email file and read it
email_file = sys.argv[1] if len(sys.argv) > 1 else "sample_phish.eml"
with open(email_file, "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)

# Pull out the key parts
sender = msg["From"]
reply_to = msg["Reply-To"]
subject = msg["Subject"]
body = msg.get_body(preferencelist=("plain",)).get_content()

# Find every link in the body
urls = re.findall(r"https?://[^\s]+", body)

# Get just the domain part (after the @) of each address
sender_domain = parseaddr(sender)[1].split("@")[-1]
reply_domain = parseaddr(reply_to)[1].split("@")[-1]

print("Subject:", subject)
print("From:", sender)
print("Reply-To:", reply_to)
print("Links found:", urls)

if sender_domain != reply_domain:
    print("RED FLAG: sender domain and reply-to domain do not match")

# Package the evidence for the AI
# Collect red flags using code (facts, not AI guesses)
red_flags = []

if sender_domain != reply_domain:
    red_flags.append(f"Sender domain ({sender_domain}) does not match Reply-To domain ({reply_domain})")

if re.search(r"[a-z][0-9][a-z]", sender_domain):
    red_flags.append(f"Sender domain ({sender_domain}) has a digit between letters, possible lookalike spelling")

urgent_words = ["urgent", "suspended", "verify", "within 24 hours", "immediately"]
found = [w for w in urgent_words if w in (subject + " " + body).lower()]
if found:
    red_flags.append(f"Urgency or threat words found: {found}")

for u in urls:
    if u.startswith("http://"):
        red_flags.append(f"Link uses unencrypted HTTP: {u}")

print("\nRED FLAGS FOUND BY CODE:")
for flag in red_flags:
    print("-", flag)

# Package the evidence for the AI
# Code decides the verdict (not the AI)
if len(red_flags) >= 3:
    verdict, confidence = "Phishing", "High"
elif len(red_flags) >= 1:
    verdict, confidence = "Suspicious", "Medium"
else:
    verdict, confidence = "Likely legitimate", "Low risk"

if verdict != "Likely legitimate" and urls:
    attack = "T1566.002 Spearphishing Link"
elif verdict != "Likely legitimate":
    attack = "T1566 Phishing"
else:
    attack = "None"

print(f"\nVERDICT (decided by code): {verdict} | Confidence: {confidence} | ATT&CK: {attack}")

# Package the evidence for the AI
evidence = f"""
Sender: {sender}
Reply-To: {reply_to}
Subject: {subject}
Links: {urls}
Red flags found by automated checks: {red_flags}
Email body:
{body}
"""

prompt = f"""You are a SOC analyst assistant. The verdict below was already decided by automated checks. Do NOT change it. Use ONLY the evidence provided. Do not invent facts.

VERDICT: {verdict}
CONFIDENCE: {confidence}

Write exactly these lines:
Summary: (2 sentences explaining why the verdict makes sense, using only the red flags and email text)
Could this be legitimate?: (1 sentence, considering an innocent explanation)
Next investigation steps: (3 specific actions, such as checking domain age, URL reputation, or the user's sign-in activity)

EVIDENCE:
{evidence}
"""

response = ollama.chat(
    model="llama3.2:3b",
    messages=[{"role": "user", "content": prompt}],
    options={"temperature": 0},
)

print("\n===== AI ANALYST NOTES =====")
print(response["message"]["content"])

# Save an incident report
import os
from datetime import datetime

os.makedirs("reports", exist_ok=True)
report_name = os.path.splitext(os.path.basename(email_file))[0]
report_path = f"reports/{report_name}_report.md"

lines = [
    "# Phishing Investigation Report",
    f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
    f"Email file: {email_file}",
    "",
    f"## Verdict (decided by code): {verdict}",
    f"- Confidence: {confidence}",
    f"- MITRE ATT&CK: {attack}",
    "",
    "## Email details",
    f"- Subject: {subject}",
    f"- From: {sender}",
    f"- Reply-To: {reply_to}",
    f"- Links: {urls}",
    "",
    "## Red flags found by code",
]
lines += [f"- {flag}" for flag in red_flags] or ["- None"]
lines += [
    "",
    "## AI analyst notes (unverified, review before acting)",
    response["message"]["content"],
    "",
    "## Analyst decision",
    "[Pending human validation]",
]

with open(report_path, "w", encoding="utf-8") as r:
    r.write("\n".join(lines))

print(f"\nReport saved to {report_path}")