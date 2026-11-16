# Password Strength Analyzer & Breach Checker

A lightweight CLI tool written in Python designed to evaluate password security using cryptographic entropy metrics, structural analysis, and the **HaveIBeenPwned API** (utilizing the k-Anonymity model for secure checks).

## Features
- **Entropy Calculation:** Measures password randomness and resistance to brute-force attacks.
- **Complexity Checks:** Validates the presence of uppercase, lowercase, numbers, and special characters.
- **Breach Lookup:** Safely queries the HaveIBeenPwned API using SHA-1 prefix hashing to check if the password has leaked.

## Installation & Usage
1. Install dependencies (requires `requests`):
   ```bash
   pip install requests
