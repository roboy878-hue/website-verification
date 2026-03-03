// Configuration
const BACKEND_URL = 'http://localhost:5000';

// Initialize event listeners
document.addEventListener('DOMContentLoaded', function() {
    const verifyForm = document.getElementById('verify-form');
    if (verifyForm) {
        verifyForm.addEventListener('submit', handleFormSubmit);
    }
});

/**
 * Handle form submission
 */
function handleFormSubmit(event) {
    event.preventDefault();

    const url = document.getElementById('url-input').value.trim();
    const resultContainer = document.getElementById('result-container');
    const errorContainer = document.getElementById('error-container');
    const verifyButton = document.getElementById('verify-button');
    const loadingSpinner = document.getElementById('loading-spinner');

    // Hide previous results and errors
    resultContainer.style.display = 'none';
    errorContainer.style.display = 'none';

    // Validate URL
    if (!url) {
        showError('Please enter a URL');
        return;
    }

    // Show loading state
    verifyButton.disabled = true;
    verifyButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';
    loadingSpinner.classList.remove('d-none');

    // Make request to backend
    verifyURL(url)
        .then(data => {
            if (data.error) {
                showError(data.error);
            } else {
                displayResults(data);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showError('An error occurred. Make sure the backend server is running at ' + BACKEND_URL);
        })
        .finally(() => {
            // Restore button state
            verifyButton.disabled = false;
            verifyButton.innerHTML = 'Verify';
            loadingSpinner.classList.add('d-none');
        });
}

/**
 * Make verification request to backend
 */
function verifyURL(url) {
    return fetch(BACKEND_URL + '/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    });
}

/**
 * Display verification results
 */
function displayResults(data) {
    const resultContainer = document.getElementById('result-container');
    const errorContainer = document.getElementById('error-container');

    // Hide error and show results
    errorContainer.style.display = 'none';

    // Populate URL
    document.getElementById('report-url').textContent = data.url || 'N/A';

    // Populate timestamp
    if (data.timestamp) {
        const date = new Date(data.timestamp);
        document.getElementById('report-timestamp').textContent = date.toLocaleString();
    }

    // Populate verdict and score
    const verdict = data.verdict || 'Unknown';
    const score = data.trust_score || 0;
    const trustLevel = data.trust_level || 'Unverified';

    const verdictSpan = document.getElementById('report-verdict');
    verdictSpan.textContent = `${verdict} (${trustLevel})`;

    // Set verdict badge color
    verdictSpan.classList.remove('bg-success', 'bg-warning', 'bg-danger');
    if (verdict === 'Genuine') {
        verdictSpan.classList.add('bg-success');
    } else if (verdict === 'Suspicious') {
        verdictSpan.classList.add('bg-warning');
    } else {
        verdictSpan.classList.add('bg-danger');
    }

    // Populate score with progress bar
    const scoreText = `${score} / 100`;
    document.getElementById('report-score').textContent = scoreText;

    const scoreBar = document.getElementById('report-score-bar');
    scoreBar.style.width = score + '%';
    scoreBar.setAttribute('aria-valuenow', score);

    // Change progress bar color based on score
    scoreBar.classList.remove('bg-success', 'bg-warning', 'bg-danger');
    if (score >= 80) {
        scoreBar.classList.add('bg-success');
    } else if (score >= 50) {
        scoreBar.classList.add('bg-warning');
    } else {
        scoreBar.classList.add('bg-danger');
    }

    // Populate details
    const detailsList = document.getElementById('report-details');
    detailsList.innerHTML = '';
    
    if (data.details) {
        for (const [key, value] of Object.entries(data.details)) {
            const listItem = document.createElement('li');
            listItem.className = 'list-group-item';
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            listItem.innerHTML = `<strong>${displayKey}:</strong> ${value || 'Not available'}`;
            detailsList.appendChild(listItem);
        }
    }

    // Populate component scores
    const componentScoresList = document.getElementById('report-component-scores');
    componentScoresList.innerHTML = '';
    
    if (data.component_scores) {
        for (const [key, value] of Object.entries(data.component_scores)) {
            const listItem = document.createElement('li');
            listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
            const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const badge = document.createElement('span');
            badge.className = 'badge bg-primary rounded-pill';
            badge.textContent = value;
            listItem.innerHTML = `<strong>${displayKey}</strong>`;
            listItem.appendChild(badge);
            componentScoresList.appendChild(listItem);
        }
    }

    // Handle warnings/alerts
    const warningsContainer = document.getElementById('warnings-container');
    const warningsList = document.getElementById('warnings-list');
    
    // Collect all warnings
    const allWarnings = [];
    if (data.details && data.details.warnings) {
        allWarnings.push(...data.details.warnings);
    }
    
    if (allWarnings.length > 0) {
        warningsList.innerHTML = '';
        allWarnings.forEach(warning => {
            const item = document.createElement('li');
            item.className = 'list-group-item';
            item.textContent = warning;
            warningsList.appendChild(item);
        });
        warningsContainer.style.display = 'block';
    } else {
        warningsContainer.style.display = 'none';
    }

    // Show results
    resultContainer.style.display = 'block';

    // Scroll to results
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Display error message
 */
function showError(message) {
    const errorContainer = document.getElementById('error-container');
    const errorMessage = document.getElementById('error-message');
    
    errorMessage.textContent = message;
    errorContainer.style.display = 'block';

    // Scroll to error
    errorContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Validate URL format
 */
function isValidURL(url) {
    try {
        new URL(url.startsWith('http') ? url : 'https://' + url);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Format domain name for display
 */
function formatDomain(domain) {
    return domain ? domain.replace('www.', '') : 'Unknown';
}

/**
 * Get trust level description
 */
function getTrustLevelDescription(score) {
    if (score >= 80) return 'Safe - Website appears to be genuine';
    if (score >= 50) return 'Caution - Website has some suspicious indicators';
    return 'Dangerous - Website is likely malicious or phishing';
}
