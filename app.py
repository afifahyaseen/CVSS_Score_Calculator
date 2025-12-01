from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import math

app = Flask(__name__)
CORS(app)

class CVSSCalculator:
    def __init__(self):
        # CVSS 3.1 Base Score Metrics
        self.attack_vector = {
            'N': 0.85,  # Network
            'A': 0.62,  # Adjacent
            'L': 0.55,  # Local
            'P': 0.2    # Physical
        }
        
        self.attack_complexity = {
            'L': 0.77,  # Low
            'H': 0.44   # High
        }
        
        self.privileges_required = {
            'N': 0.85,  # None
            'L': 0.62,  # Low
            'H': 0.27   # High
        }
        
        self.privileges_required_changed = {
            'N': 0.85,  # None
            'L': 0.68,  # Low
            'H': 0.5    # High
        }
        
        self.user_interaction = {
            'N': 0.85,  # None
            'R': 0.62   # Required
        }
        
        self.scope = {
            'U': 'Unchanged',
            'C': 'Changed'
        }
        
        self.impact_metrics = {
            'N': 0.0,   # None
            'L': 0.22,  # Low
            'H': 0.56   # High
        }

    def calculate_base_score(self, av, ac, pr, ui, s, c, i, a):
        """
        Calculate CVSS 3.1 Base Score
        
        Args:
            av: Attack Vector (N/A/L/P)
            ac: Attack Complexity (L/H)
            pr: Privileges Required (N/L/H)
            ui: User Interaction (N/R)
            s: Scope (U/C)
            c: Confidentiality Impact (N/L/H)
            i: Integrity Impact (N/L/H)
            a: Availability Impact (N/L/H)
        """
        
        # Get metric values
        av_val = self.attack_vector[av]
        ac_val = self.attack_complexity[ac]
        ui_val = self.user_interaction[ui]
        
        # Privileges Required depends on Scope
        if s == 'C':
            pr_val = self.privileges_required_changed[pr]
        else:
            pr_val = self.privileges_required[pr]
        
        # Impact metrics
        c_val = self.impact_metrics[c]
        i_val = self.impact_metrics[i]
        a_val = self.impact_metrics[a]
        
        # Calculate Impact Sub-Score (ISS)
        iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
        
        # Calculate Impact Score
        if s == 'U':
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Exploitability Score
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if s == 'U':
                base_score = min(10.0, impact + exploitability)
            else:
                base_score = min(10.0, 1.08 * (impact + exploitability))
        
        # Round up to one decimal place
        base_score = math.ceil(base_score * 10) / 10
        
        return {
            'base_score': base_score,
            'impact_score': round(impact, 1),
            'exploitability_score': round(exploitability, 1),
            'severity': self.get_severity_rating(base_score)
        }
    
    def get_severity_rating(self, score):
        """Get severity rating based on CVSS score"""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"

calculator = CVSSCalculator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        data = request.json
        
        # Extract CVSS metrics from request
        av = data.get('attack_vector')
        ac = data.get('attack_complexity')
        pr = data.get('privileges_required')
        ui = data.get('user_interaction')
        s = data.get('scope')
        c = data.get('confidentiality')
        i = data.get('integrity')
        a = data.get('availability')
        
        # Validate all required parameters are present
        required_params = [av, ac, pr, ui, s, c, i, a]
        if not all(param is not None for param in required_params):
            return jsonify({'error': 'Missing required CVSS parameters'}), 400
        
        # Calculate CVSS score
        result = calculator.calculate_base_score(av, ac, pr, ui, s, c, i, a)
        
        # Add vector string
        vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        result['vector_string'] = vector_string
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)

