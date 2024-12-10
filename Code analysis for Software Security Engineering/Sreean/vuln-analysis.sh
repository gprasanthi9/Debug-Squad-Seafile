#!/bin/bash

# Script to find vulnerabilities in the Seafile source code
# CWEs of interest:
# 1. CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
# 2. CWE-287: Improper Authentication
# 3. CWE-502: Deserialization of Untrusted Data
# 4. CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-Site Scripting - XSS)
# 5. CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
# 6. CWE-611: Improper Restriction of XML External Entity Reference (XXE)
# 7. CWE-798: Use of Hard-coded Credentials
# 8. CWE-284: Improper Access Control
# 9. CWE-522: Insufficiently Protected Credentials
# 10. CWE-400: Uncontrolled Resource Consumption (Resource Exhaustion)

# Define the source directory
SOURCE_DIR="$HOME/IdeaProjects/seafile-server/seafile-server"

# Output directory for results
OUTPUT_DIR="$HOME/IdeaProjects/seafile-server/vuln-analysis-results"
mkdir -p $OUTPUT_DIR

# Analyze vulnerabilities in parts
# Split analysis into multiple stages to avoid overwhelming output

# Part 1: CWE-200, CWE-287, CWE-502, CWE-79, CWE-89

# Search for CWE-200: Sensitive Information Exposure
# Look for logging, printf statements that might expose sensitive information
grep -r -E "(password|secret|credential|token)" $SOURCE_DIR > $OUTPUT_DIR/cwe-200.txt

# Search for CWE-287: Improper Authentication
# Look for improperly configured authentication methods, weak checks
grep -r -E "(auth|login|authenticate)" $SOURCE_DIR > $OUTPUT_DIR/cwe-287.txt

# Search for CWE-502: Deserialization of Untrusted Data
# Look for deserialization functions such as unserialize, pickle, etc.
grep -r -E "(unserialize|pickle|load)" $SOURCE_DIR > $OUTPUT_DIR/cwe-502.txt

# Search for CWE-79: Cross-Site Scripting (XSS)
# Look for unsanitized input in HTML output, functions like echo, print, etc.
grep -r -E "(echo|print|html)" $SOURCE_DIR > $OUTPUT_DIR/cwe-79.txt

# Search for CWE-89: SQL Injection
# Look for SQL queries without proper sanitization
grep -r -E "(SELECT|INSERT|UPDATE|DELETE)" $SOURCE_DIR > $OUTPUT_DIR/cwe-89.txt

# Generate a partial summary report for Part 1
echo "Part 1 Vulnerability Search Completed. Check $OUTPUT_DIR for detailed results." > $OUTPUT_DIR/part1-summary.txt

# Part 2: CWE-611, CWE-798, CWE-284, CWE-522, CWE-400

# Search for CWE-611: XML External Entity (XXE)
# Look for XML parsing without secure settings
grep -r -E "(xml|XMLReader|SAXParser)" $SOURCE_DIR > $OUTPUT_DIR/cwe-611.txt

# Search for CWE-798: Hard-coded Credentials
# Look for hard-coded usernames, passwords
grep -r -E "(username|password)" $SOURCE_DIR > $OUTPUT_DIR/cwe-798.txt

# Search for CWE-284: Improper Access Control
# Look for weak or missing access control mechanisms
grep -r -E "(permission|access|acl)" $SOURCE_DIR > $OUTPUT_DIR/cwe-284.txt

# Search for CWE-522: Insufficiently Protected Credentials
# Look for credentials being transmitted or stored without encryption
grep -r -E "(ssl|tls|encryption|plaintext)" $SOURCE_DIR > $OUTPUT_DIR/cwe-522.txt

# Search for CWE-400: Resource Exhaustion
# Look for loops or functions that could lead to uncontrolled resource consumption
grep -r -E "(while|for|sleep|resource)" $SOURCE_DIR > $OUTPUT_DIR/cwe-400.txt

# Generate a partial summary report for Part 2
echo "Part 2 Vulnerability Search Completed. Check $OUTPUT_DIR for detailed results." > $OUTPUT_DIR/part2-summary.txt

# Final summary
echo "Vulnerability Search Completed for all parts. Check $OUTPUT_DIR for full analysis results."

# Auto-analysis and Verdict Generation
VERDICT_FILE="$OUTPUT_DIR/vulnerability-verdict.txt"
echo "--- Vulnerability Analysis Verdict ---" > $VERDICT_FILE

for FILE in $OUTPUT_DIR/*.txt; do
  CWE=$(basename $FILE .txt)
  if [ -s $FILE ]; then
    echo "$CWE: Potential issues found. Review $FILE for details." >> $VERDICT_FILE
  else
    echo "$CWE: No significant issues detected." >> $VERDICT_FILE
  fi
done

echo "Auto-analysis completed. Check $VERDICT_FILE for a summary of potential vulnerabilities."
