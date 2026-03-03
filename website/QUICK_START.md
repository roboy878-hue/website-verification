# Quick Start Guide

## Step 1: Start the Backend Server

Open a terminal and run:
```bash
cd backend
py app.py
```

You should see:
```
 * Debug mode: on
 * Running on http://0.0.0.0:5000
```

**Important**: Keep this terminal open while testing the application.

## Step 2: Start the Frontend Server

Open another terminal and run:
```bash
cd frontend
py -m http.server 8000
```

You should see:
```
Serving HTTP on 0.0.0.0 port 8000 ...
```

## Step 3: Open the Application

Open your web browser and go to:
```
http://localhost:8000
```

## Testing the System

Once the application is open, try these test URLs:

1. **Legitimate Website**
   - URL: `https://www.google.com`
   - Expected: High trust score (80+), Genuine verdict

2. **Another Legitimate Site**
   - URL: `https://www.github.com`
   - Expected: High trust score (80+), Genuine verdict

3. **Test with just domain** (without https://)
   - URL: `example.com`
   - System auto-prepends `https://`

## Troubleshooting

### "Backend is not responding"
- Make sure Flask server is running on port 5000
- Check the terminal where you started `py app.py`

### CORS errors
- Verify Flask-CORS is installed: `py -m pip list | findstr Flask-CORS`
- If not, install: `py -m pip install Flask-CORS`

### Port already in use
- If port 5000 is busy: modify `app.py` to use a different port
- If port 8000 is busy: use `py -m http.server 9000` and open `http://localhost:9000`

## Architecture Notes

- **Backend**: Flask REST API on port 5000
- **Frontend**: HTML/CSS/JavaScript on port 8000
- **Database**: SQLite (auto-created as `backend/verification.db`)
- **Logs**: Check Flask terminal for detailed verification results

## API Endpoints (for testing with Postman/cURL)

```bash
# Health check
curl http://localhost:5000

# Verify a URL
curl -X POST http://localhost:5000/verify \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://example.com\"}"

# Get history
curl http://localhost:5000/history
```

## Performance Notes

- First URL check may take ~5-10 seconds (DNS resolution, SSL fetch, etc.)
- Subsequent checks are faster
- Content analysis (page fetch) adds ~3-5 seconds
- WHOIS lookup may timeout on some domains (30+ seconds won't block)

---

**Ready to verify websites!** 🔒
