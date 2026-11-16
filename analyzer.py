import hashlib
import math
import re
import sys


def calculate_entropy(password):
    """Calculate password entropy (brute-force complexity)."""
    if not password:
        return 0
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
    return round(entropy, 2)


def check_pwned_api(password):
    """Check password against HaveIBeenPwned database using k-Anonymity API."""
    sha1_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "Error connecting to HIBP API"

        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except Exception as e:
        return f"API check failed: {str(e)}"


def evaluate_password(password):
    print("\n" + "=" * 40)
    print("      PASSWORD SECURITY ANALYSIS")
    print("=" * 40)

    length = len(password)
    entropy = calculate_entropy(password)

    print(f"[*] Length: {length} characters")
    print(f"[*] Entropy: {entropy} bits")

    # Basic criteria checks
    checks = {
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Numbers": bool(re.search(r"[0-9]", password)),
        "Special characters": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }

    for criterion, passed in checks.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"    - {criterion}: {status}")

    # Check for breaches
    print("[*] Checking HaveIBeenPwned database...")
    pwned_count = check_pwned_api(password)

    if isinstance(pwned_count, int):
        if pwned_count > 0:
            print(
                f"    [!] WARNING: This password has been found in {pwned_count} data breaches!"
            )
        else:
            print(
                "    [+] Good news! This password was not found in known breaches."
            )
    else:
        print(f"    [!] {pwned_count}")

    print("=" * 40 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        pwd = sys.argv[1]
    else:
        pwd = input("Enter password to analyze: ")
    evaluate_password(pwd)
