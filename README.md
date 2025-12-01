# CVSS Base Score Calculator

A web-based CVSS (Common Vulnerability Scoring System) 3.1 Base Score Calculator with a Python Flask backend and HTML/CSS/JavaScript frontend.

## Features

- Complete CVSS 3.1 Base Score calculation
- Modern, responsive web interface
- Real-time form validation
- Detailed score breakdown (Impact, Exploitability)
- CVSS vector string generation
- Color-coded severity ratings

## Installation & Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Open your browser and navigate to:**
   ```
   http://localhost:5000
   ```

## How to Use

1. Select values for all 8 CVSS base metrics:
   - **Attack Vector (AV)**: Network, Adjacent, Local, or Physical
   - **Attack Complexity (AC)**: Low or High
   - **Privileges Required (PR)**: None, Low, or High
   - **User Interaction (UI)**: None or Required
   - **Scope (S)**: Unchanged or Changed
   - **Confidentiality Impact (C)**: None, Low, or High
   - **Integrity Impact (I)**: None, Low, or High
   - **Availability Impact (A)**: None, Low, or High

2. Click "Calculate CVSS Score" to get:
   - Base Score (0.0 - 10.0)
   - Severity Rating (None, Low, Medium, High, Critical)
   - Impact Score
   - Exploitability Score
   - CVSS Vector String

## Technical Details

- **Backend**: Python Flask with CORS support
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **CVSS Version**: 3.1
- **Port**: 5000 (localhost)

## API Endpoints

- `GET /` - Main application interface
- `POST /calculate` - Calculate CVSS score
- `GET /health` - Health check endpoint

## File Structure

```
├── app.py              # Flask backend with CVSS calculation logic
├── templates/
│   └── index.html      # Frontend interface
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## CVSS 3.1 Implementation

This calculator implements the official CVSS 3.1 specification with accurate:
- Base score calculation formula
- Impact sub-score calculation
- Exploitability score calculation
- Scope-dependent privilege required adjustments
- Proper rounding (ceiling to one decimal place)
