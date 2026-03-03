# Website Genuineness Verification System

A web-based tool to verify the authenticity and safety of websites by analyzing multiple security indicators.

## Features

- **URL Verification**: Input any URL and get detailed security analysis
- **Multi-layer Detection**:
  - SSL Certificate Validation
  - Domain Age Analysis  
  - Blacklist Checks
  - Content Analysis for Phishing Patterns
  - IP Intelligence
  - Reputation Scoring

- **Trust Scoring**: 0-100 scale with verdicts (Genuine, Suspicious, Malicious)
- **Detailed Reports**: Component-wise analysis with warnings
- **Verification History**: Store and retrieve past checks

## Project Structure

```
website/
├── backend/
│   ├── app.py                 # Flask application & routes
│   ├── requirements.txt        # Python dependencies
│   ├── .env                    # Environment configuration
│   ├── verification.db         # SQLite database (auto-created)
│   └── modules/
│       ├── url_parser.py       # URL parsing & validation
│       ├── ssl_checker.py      # SSL certificate validation
│       ├── whois_lookup.py     # Domain age & WHOIS info
│       ├── blacklist_check.py  # Threat database checks
│       ├── content_analyzer.py # Page content scanning
│       ├── ip_intelligence.py  # IP geolocation & risk analysis
│       └── score_engine.py     # Score aggregation & verdict
│
├── frontend/
│   ├── index.html              # Main UI
│   ├── style.css               # Styling
│   └── script.js               # Frontend logic
│
└── Website_Verification_Report.txt  # Project documentation
```

## Installation & Setup

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- Modern web browser

### Step 1: Install Dependencies

Navigate to the backend directory and install required packages:

```bash
cd website/backend
pip install -r requirements.txt
```

### Step 2: Configure Environment (Optional)

Edit `.env` to add API keys for enhanced detection:
- VirusTotal API key (virustotal.com)
- Google Safe Browsing API key (Google Cloud Console)
- IPInfo.io API key (ipinfo.io)

```
VIRUSTOTAL_API_KEY=your_key_here
SAFE_BROWSING_API_KEY=your_key_here
```

### Step 3: Start the Backend Server

From the backend directory:

```bash
python app.py
```

The server will start on `http://localhost:5000`

Expected output:
```
* Debug mode: on
* Running on http://0.0.0.0:5000
```

### Step 4: Open the Frontend

1. Navigate to the `frontend` folder
2. Open `index.html` in your web browser, or
3. Serve it with a local server (recommended):

```bash
# Option A: Using Python's built-in server
cd frontend
python -m http.server 8000

# Then open: http://localhost:8000
```

## Usage

1. **Enter a URL**: Type any website URL (e.g., `https://example.com` or just `example.com`)
2. **Click Verify**: The system will analyze the website
3. **Review Results**: 
   - Check the Trust Score (0-100)
   - Read the Verdict (Genuine/Suspicious/Malicious)
   - Review detailed findings for each check

## Scoring Weights

| Check | Weight | Description |
|-------|--------|-------------|
| Blacklist Status | 35% | Threat database matches |
| SSL Certificate | 20% | Certificate validity & issuer |
| Domain Age | 20% | Registration age (newer = riskier) |
| Content Analysis | 15% | Phishing patterns & malicious scripts |
| IP Intelligence | 10% | Location, VPN/proxy, datacenter flags |

## Verdict Thresholds

- **Genuine** (80-100): Website appears safe and trustworthy
- **Suspicious** (50-79): Website has warnings, use caution
- **Malicious** (0-49): Website is likely phishing or malware

## API Endpoints

### Verify URL
```
POST /verify
Content-Type: application/json

{
    "url": "https://example.com"
}

Response:
{
    "url": "https://example.com",
    "domain": "example.com",
    "trust_score": 85,
    "trust_level": "Safe",
    "verdict": "Genuine",
    "details": {...},
    "component_scores": {...},
    "timestamp": "2026-03-03T..."
}
```

### Get Verification History
```
GET /history

Response:
[
    {
        "id": 1,
        "url": "https://example.com",
        "verdict": "Genuine",
        "trust_score": 85,
        "created_at": "2026-03-03T..."
    },
    ...
]
```

### Health Check
```
GET /

Response:
{
    "status": "Backend is running!",
    "timestamp": "2026-03-03T..."
}
```

## Testing

Try these URLs to test the system:

1. **Legitimate Site**: `https://www.google.com` → Expected: Genuine
2. **New Domain**: Create a brand-new domain → Expected: Lower score
3. **Invalid URL**: `not-a-real-website.invalid` → Expected: Error handling

## Limitations & Future Improvements

### Current Limitations:
- API keys needed for full blacklist functionality
- Limited to public DNS resolution
- Content analysis is basic pattern matching
- No machine learning models

### Future Enhancements:
- Real-time threat intelligence feeds
- Machine learning based phishing detection
- Screenshot comparison with brand sites
- Extended validation reports with PDF export
- User authentication and saved history
- Batch URL verification API

## Troubleshooting

### "Backend is running" error in browser
- Make sure Flask server is running on `http://localhost:5000`
- Check firewall settings

### SSL certificate errors
- Domain must be accessible from your network
- Some certificates may not be readable on the first attempt

### Timeout errors
- Increase timeout values in configuration
- Check internet connectivity

## Security Notes

- This tool is for educational and security awareness purposes
- Always perform additional verification before trusting results
- Don't rely solely on this tool for critical security decisions
- Keep API keys secure and use environment variables

## Architecture

The system uses a 3-tier architecture:

```
┌─────────────────┐
│  Frontend (UI)  │
│  HTML/CSS/JS    │
└────────┬────────┘
         │ HTTP API
         ↓
┌─────────────────────────────┐
│   Flask Backend (Logic)     │
│  - URL Parser               │
│  - SSL Checker              │
│  - WHOIS Lookup             │
│  - Blacklist Check          │
│  - Content Analyzer         │
│  - IP Intelligence          │
│  - Score Engine             │
└────────┬────────────────────┘
         │ SQL
         ↓
┌──────────────────┐
│ SQLite Database  │
│ (Verification    │
│  Reports & Data) │
└──────────────────┘
```

## Contributing

To extend this system:

1. Create new modules in `backend/modules/`
2. Update the scoring weights in `score_engine.py`
3. Add new API endpoints in `app.py`
4. Enhance frontend UI in `style.css` and `script.js`

## License

Educational project for Codethon 2026

## Support

For issues or questions:
1. Check the example URLs in the testing section
2. Verify all dependencies are installed
3. Check Flask server logs for errors
4. Ensure ports 5000 and 8000 are available

---

**Report Date**: March 3, 2026  
**Event**: Codethon 2026 — Innovate, Create, Inspire
