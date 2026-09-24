#!/usr/bin/env bash
#
# phishguard — heuristic phishing-URL analyzer
# https://github.com/<your-username>/phishguard
#
# Usage: ./phishguard.sh <url>
#        ./phishguard.sh -f urls.txt
#
# Scores a URL against a set of well-known phishing indicators and
# prints a risk rating with an explanation for each flag raised.
# This is a heuristic teaching tool, NOT a substitute for a real
# threat-intel feed or browser safe-browsing check.

set -uo pipefail
VERSION="1.0.0"

# ---------- colors ----------
if [[ -t 1 ]]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
  C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'
  C_CYAN='\033[36m'; C_MAGENTA='\033[35m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_MAGENTA=''
fi

flag()  { printf "  ${C_YELLOW}⚑${C_RESET} %s ${C_DIM}(+%s)${C_RESET}\n" "$1" "$2"; }
ok()    { printf "  ${C_GREEN}✔${C_RESET} %s\n" "$1"; }

print_banner() {
  printf "${C_MAGENTA}${C_BOLD}"
  cat <<'EOF'
        _     _     _                       _
 _ __  | |__ (_)___| |__   __ _ _   _  __ _ _ __ __| |
| '_ \ | '_ \| / __| '_ \ / _` | | | |/ _` | '__/ _` |
| |_) || | | | \__ \ | | | (_| | |_| | (_| | | | (_| |
| .__/ |_| |_|_|___/_| |_|\__, |\__,_|\__,_|_|  \__,_|
|_|                       |___/
EOF
  printf "${C_RESET}${C_DIM}  phishing URL heuristic scanner · v${VERSION}${C_RESET}\n\n"
}

usage() {
  print_banner
  cat <<EOF
${C_BOLD}Usage:${C_RESET}
  $(basename "$0") <url>          analyze one URL
  $(basename "$0") -f <file>      analyze one URL per line
  $(basename "$0") -h             show this help

${C_BOLD}Examples:${C_RESET}
  $(basename "$0") "http://paypa1-secure-login.tk/verify"
  $(basename "$0") -f suspicious_links.txt
EOF
}

# well-known shortener domains (not inherently malicious, but hide the real target)
SHORTENERS="bit.ly|tinyurl.com|t.co|goo.gl|ow.ly|is.gd|buff.ly|rebrand.ly|cutt.ly|shorte.st"
SUSPICIOUS_TLDS="tk|ml|ga|cf|gq|xyz|top|club|work|click|link|country|kim|men|loan|download"
BRAND_KEYWORDS="paypal|google|facebook|apple|microsoft|amazon|netflix|instagram|bank|irs|revenue|wellsfargo|chase|dhl|fedex"
URGENT_KEYWORDS="verify|secure|update|confirm|suspend|locked|urgent|expire|limited|unusual"

analyze_url() {
  local url="$1"
  local score=0
  local -a hits=()

  # strip scheme for host extraction
  local no_scheme="${url#http://}"
  no_scheme="${no_scheme#https://}"
  local host="${no_scheme%%/*}"
  host="${host%%\?*}"
  local host_lc
  host_lc=$(echo "$host" | tr '[:upper:]' '[:lower:]')

  printf "${C_BOLD}URL:${C_RESET} %s\n" "$url"
  printf "${C_DIM}Host: %s${C_RESET}\n\n" "$host"

  # 1. no https
  if [[ "$url" != https://* ]]; then
    hits+=("არ იყენებს HTTPS-ს — მონაცემები დაუშიფრავად გადაიცემა|15")
  fi

  # 2. IP address as host instead of domain name
  if [[ "$host_lc" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3} ]]; then
    hits+=("დომენის ნაცვლად IP მისამართია გამოყენებული — ტიპური ფიშინგის ნიშანი|25")
  fi

  # 3. @ symbol trick (browser ignores everything before @)
  if [[ "$url" == *"@"* ]]; then
    hits+=("URL შეიცავს '@' სიმბოლოს — შეიძლება მალავდეს ნამდვილ დანიშნულებას|25")
  fi

  # 4. known URL shortener
  if echo "$host_lc" | grep -qE "^($SHORTENERS)$"; then
    hits+=("URL შემოკლების სერვისია (${host}) — ნამდვილი დანიშნულება დამალულია|10")
  fi

  # 5. suspicious / cheap TLD
  local tld="${host_lc##*.}"
  if echo "$tld" | grep -qE "^($SUSPICIOUS_TLDS)$"; then
    hits+=("იშვიათი/იაფი დომენის ზონაა (.$tld) — ხშირად გამოიყენება ფიშინგში|15")
  fi

  # 6. excessive subdomains
  local dot_count
  dot_count=$(echo "$host_lc" | tr -cd '.' | wc -c)
  if [[ "$dot_count" -ge 3 ]]; then
    hits+=("არაჩვეულებრივად ბევრი სუბდომენია ($host) — მცდელობა შეცდომაში შეგიყვანოთ|15")
  fi

  # 7. punycode / homograph attack
  if [[ "$host_lc" == *xn--* ]]; then
    hits+=("Punycode დაშიფვრა დომენში — შესაძლო სახის-იდენტური სიმბოლოების შეტევა (homograph)|25")
  fi

  # 8. brand name mentioned but not as the actual registered domain
  for brand in paypal google facebook apple microsoft amazon netflix instagram bank; do
    if [[ "$host_lc" == *"$brand"* ]]; then
      # crude check: is it something like paypal.com exactly, or paypal-something.xyz?
      if [[ ! "$host_lc" =~ ^(www\.)?${brand}\.[a-z]{2,6}$ ]]; then
        hits+=("ბრენდის სახელი '${brand}' გვხვდება დომენში, მაგრამ ეს არ არის ოფიციალური დომენი — ტიპური typosquatting|30")
        break
      fi
    fi
  done

  # 9. urgency / social-engineering keywords in the path
  local matched_kw
  matched_kw=$(echo "$url" | tr '[:upper:]' '[:lower:]' | grep -oE "$URGENT_KEYWORDS" | head -1 || true)
  if [[ -n "$matched_kw" ]]; then
    hits+=("URL-ში ჩნდება 'გადაუდებლობის' სიტყვა ('${matched_kw}') — სოციალური ინჟინერიის ტიპური ხერხი|10")
  fi

  # 10. hyphen-heavy host (common in lookalike domains: paypal-secure-login.com)
  local hyphen_count
  hyphen_count=$(echo "$host_lc" | tr -cd '-' | wc -c)
  if [[ "$hyphen_count" -ge 2 ]]; then
    hits+=("დომენში ბევრი დეფისია ($host) — ხშირად ყალბი მსგავსი დომენების ნიშანია|10")
  fi

  # sum score
  for h in "${hits[@]}"; do
    score=$((score + ${h##*|}))
  done

  if [[ ${#hits[@]} -eq 0 ]]; then
    ok "ცხადი ფიშინგის ნიშნები არ აღმოჩენილა"
  else
    for h in "${hits[@]}"; do
      flag "${h%|*}" "${h##*|}"
    done
  fi

  echo
  local verdict color
  if   [[ $score -ge 50 ]]; then verdict="მაღალი რისკი — სავარაუდოდ ფიშინგია"; color="$C_RED"
  elif [[ $score -ge 20 ]]; then verdict="საშუალო რისკი — სიფრთხილეა საჭირო"; color="$C_YELLOW"
  else                            verdict="დაბალი რისკი"; color="$C_GREEN"
  fi
  printf "${C_BOLD}რისკის ქულა:${C_RESET} %s/100   ${color}${C_BOLD}%s${C_RESET}\n" "$score" "$verdict"
  printf "${C_DIM}────────────────────────────────────────────────${C_RESET}\n\n"
}

# ---------- main ----------
if [[ $# -eq 0 ]]; then
  usage; exit 1
fi

case "$1" in
  -h|--help) usage; exit 0 ;;
  -f|--file)
    [[ -z "${2:-}" ]] && { echo "გთხოვთ მიუთითოთ ფაილი: -f urls.txt"; exit 1; }
    print_banner
    while IFS= read -r line; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      analyze_url "$line"
    done < "$2"
    ;;
  *)
    print_banner
    analyze_url "$1"
    ;;
esac
