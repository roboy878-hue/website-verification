# Logger Setup & Debugging Guide

## Overview

Comprehensive logging has been added throughout the **Website Genuineness Verification System** for easy debugging and issue identification. Logs are written to both **console** and **file** simultaneously.

## Log File Location

```
c:\Users\ELCOT\website\backend\logs\verification.log
```

The log file automatically rotates when it exceeds 10MB (keeps last 10 backups).

## Log Format

Each log entry follows this format:

```
TIMESTAMP - LOGGER_NAME - LOG_LEVEL - [FILE:LINE] - MESSAGE
```

Example:
```
2026-03-03 19:43:10,123 - modules.ssl_checker - INFO - [ssl_checker.py:62] - SSL check completed for google.com: Status=Valid, Score=100
```

## Log Levels

- **DEBUG**: Detailed information, typically of interest only when diagnosing problems
- **INFO**: Confirmation that things are working as expected
- **WARNING**: Something unexpected happened, or could happen
- **ERROR**: Serious problem, function may not work as expected
- **CRITICAL**: Very serious error, program may not continue

## Request Flow in Logs

Each URL verification follows this sequence in the logs:

### 1. Request Received
```
[VERIFY REQUEST] Starting verification for URL: https://example.com
```

### 2. URL Parsing
```
[STEP 1] Parsing URL...
[STEP 1] URL parsed successfully: {...}
```

### 3. Component Checks
```
[CHECK] Starting SSL Certificate check...
[CHECK] Starting WHOIS/Domain Age check...
[CHECK] Starting Blacklist check...
[CHECK] Starting Content Analysis...
[CHECK] Starting IP Intelligence check...
```

Each check includes detailed results.

### 4. Score Calculation
```
[SCORE ENGINE] Starting score calculation...
[SCORE ENGINE] Extracted component scores - Blacklist: 100, SSL: 100, Domain Age: 75, Content: 100, IP: 80
[SCORE ENGINE] Final score: 88.5, Verdict: Genuine, Trust Level: Safe
```

### 5. Request Complete
```
[VERIFY REQUEST] Verification completed successfully. Final verdict: Genuine (Score: 88.5)
```

## Viewing Logs

### Real-time Monitoring
```powershell
# Watch logs as they arrive (PowerShell)
Get-Content c:\Users\ELCOT\website\backend\logs\verification.log -Tail 50 -Wait
```

### View Last N Lines
```powershell
# View last 100 lines
Get-Content c:\Users\ELCOT\website\backend\logs\verification.log -Tail 100
```

### Search for Errors
```powershell
# Find all errors
Select-String "ERROR" c:\Users\ELCOT\website\backend\logs\verification.log
```

### Filter by Module
```powershell
# View only SSL checker logs
Select-String "ssl_checker" c:\Users\ELCOT\website\backend\logs\verification.log
```

## Debugging Examples

### Problem: URL shows "Suspicious" verdict

**Solution**: Check the logs for component scores
```powershell
Select-String "component scores" c:\Users\ELCOT\website\backend\logs\verification.log -Context 2
```

Look for low scores:
```
- blacklist: 100  (Good)
- ssl: 30        (BAD - certificate invalid/expired)
- domain_age: 50 (MEDIUM - relatively new domain)
- content: 100   (Good)
- ip: 80         (Good)
```

### Problem: SSL check is failing

**Solution**: Search for SSL errors
```powershell
Select-String "SSL error\|ssl_checker.*ERROR" c:\Users\ELCOT\website\backend\logs\verification.log
```

Example error:
```
2026-03-03 19:42:56,243 - modules.ssl_checker - ERROR - [ssl_checker.py:84] - 
Unexpected error during SSL check for example.com: timeout
```

### Problem: Domain age always shows "Unknown"

**Solution**: Check WHOIS lookup logs
```powershell
Select-String "WHOIS\|whois_lookup" c:\Users\ELCOT\website\backend\logs\verification.log
```

The WHOIS module logs show if it's a network connection issue:
```
2026-03-03 19:42:58,585 - modules.whois_lookup - ERROR - [whois_lookup.py:68] - 
WHOIS lookup failed for google.com: [WinError 10061] No connection could be made
```

### Problem: Content analysis too strict/lenient

**Solution**: Monitor content analyzer logs
```powershell
Select-String "content_analyzer\|Content analysis verdict" c:\Users\ELCOT\website\backend\logs\verification.log
```

Example:
```
2026-03-03 19:43:00,600 - modules.content_analyzer - WARNING - [content_analyzer.py:100] - 
Content analysis verdict for https://example.com: SUSPICIOUS (3 warnings)

2026-03-03 19:43:00,600 - modules.content_analyzer - WARNING - [content_analyzer.py:78] - 
Suspicious pattern 'eval(' found 1 times in https://example.com
```

## Log Modules & Their Responsibilities

| Module | Logs | Purpose |
|--------|------|---------|
| `__main__` | Request flow, steps | Overall verification pipeline |
| `url_parser` | URL parsing, validation | Extracts domain components |
| `ssl_checker` | Certificate status, expiry | SSL/TLS validation |
| `whois_lookup` | Domain age, registrar | WHOIS data retrieval |
| `blacklist_check` | Threat database results | Malicious URL detection |
| `content_analyzer` | Content patterns found | Phishing pattern detection |
| `ip_intelligence` | IP resolution, VPN/proxy flags | IP-based threat detection |
| `score_engine` | Weighted calculations, verdict logic | Final scoring & verdict |

## Performance Analysis

Use logs to identify slow checks:

```powershell
# Get a summary of time between log entries
Get-Content c:\Users\ELCOT\website\backend\logs\verification.log | 
  Select-String "\[CHECK\] Starting|completed" |
  Select-Object -Last 20
```

## Clearing Old Logs

To start fresh:
```powershell
# Delete current log
Remove-Item c:\Users\ELCOT\website\backend\logs\verification.log

# Archived logs (10MB+ files)
Remove-Item c:\Users\ELCOT\website\backend\logs\verification.log.*
```

## Configuration

To change logging behavior, edit the `setup_logging()` function in `backend/app.py`:

- **Log Level**: Change `DEBUG` to `WARNING` if too verbose
- **File Size**: Modify `maxBytes=10485760` (currently 10MB)
- **Backup Count**: Change `backupCount=10` to keep more/fewer archived logs
- **Format**: Modify `log_format` string to customize output

## Issues Fixed with Logging

✅ **SSL Certificate Error**: Found `'datetime.datetime' object is not callable` - property access issue  
✅ **Content Analysis False Positives**: Identified overly strict pattern matching  
✅ **Unicode Encoding Errors**: Detected special character issues in terminal  
✅ **WHOIS Network Issues**: Identified connection refused errors

---

**The logging system is now your window into what the verification engine is doing at every step!**
