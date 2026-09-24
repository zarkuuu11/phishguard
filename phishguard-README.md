# phishguard

A single-file Bash tool that scores URLs against well-known phishing indicators and prints a risk rating with an explanation for every flag raised.

Built as a teaching / awareness tool: it doesn't call any external threat-intel API — everything is a transparent, explainable heuristic, so you can read the script and understand exactly *why* a URL was flagged.

## What it checks

| Check | Why it matters |
|---|---|
| No HTTPS | Credentials sent in plaintext |
| IP address instead of a domain name | Classic way to hide the real host |
| `@` symbol in the URL | Browsers ignore everything before `@` — used to disguise the real destination |
| Known URL shortener | Hides the real target link |
| Suspicious/cheap TLD (`.tk`, `.xyz`, `.top`, …) | Disproportionately used in phishing campaigns |
| Excessive subdomains | `login.paypal.com.verify-account.tk` style tricks |
| Punycode (`xn--`) | Possible homograph / lookalike-character attack |
| Brand name in a non-official domain | Typosquatting (`paypa1-secure.tk`) |
| Urgency keywords (`verify`, `suspended`, `confirm`, …) | Classic social-engineering pressure tactics |
| Hyphen-heavy domain | Common in fake lookalike domains |

Each hit adds points to a 0–100 risk score:

- **0–19** → low risk
- **20–49** → medium risk, be careful
- **50+** → high risk, likely phishing

## Usage

```bash
chmod +x phishguard.sh

# analyze a single URL
./phishguard.sh "http://paypa1-secure-login.tk/verify"

# analyze a list of URLs (one per line)
./phishguard.sh -f suspicious_links.txt
```

## Example

```
URL: http://paypa1-secure-login.tk/verify@account
Host: paypa1-secure-login.tk

  ⚑ არ იყენებს HTTPS-ს (+15)
  ⚑ URL შეიცავს '@' სიმბოლოს (+25)
  ⚑ იშვიათი/იაფი დომენის ზონაა (.tk) (+15)
  ⚑ URL-ში ჩნდება 'გადაუდებლობის' სიტყვა ('secure') (+10)
  ⚑ დომენში ბევრი დეფისია (+10)

რისკის ქულა: 75/100   მაღალი რისკი — სავარაუდოდ ფიშინგია
```

## Limitations

This is a **heuristic** scanner, not a real-time threat-intel lookup. It:

- Does not check domain age, WHOIS, or certificate transparency logs
- Does not visit the URL or check page content
- Can produce false positives (e.g. a legitimate site with many subdomains) and false negatives (a well-crafted phishing domain with no matching brand keyword)

It is meant to illustrate *how* automated phishing detection works, for coursework and awareness — not to replace a browser's built-in safe-browsing protection or a production security product.

## License

MIT — see [LICENSE](LICENSE).
