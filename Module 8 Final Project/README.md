# Secret Scanner

**Author:** Jason Hollin  
**Date:** October 2025  
**Course:** SDEV245  

A simple Python CLI tool that scans files or directories for hardcoded secrets such as API keys, passwords, tokens, and private keys.

---

## Features
- Accepts a directory path or single file as input.
- Uses regex to detect common secret patterns.
- Outputs a report showing:
  - Filename  
  - Line number  
  - Masked match string  
- Includes logging and a clean CLI interface (`argparse`).

---

## How to Run
1. Clone or download this repository.
2. Make sure you have **Python 3.9+** installed.
3. Open a terminal and navigate to the project folder.
4. Run the scanner using one of the following commands:

```bash
# Scan the example files and display results in the terminal
python main.py --path ./example_files

# Save results to a CSV file
python main.py -p ./example_files -f csv -o report.csv
