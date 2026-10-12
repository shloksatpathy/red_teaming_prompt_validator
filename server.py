from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import hashlib
from pathlib import Path
from dotenv import load_dotenv
from prompt_injection_detector import PromptInjectionDetector
from harden import harden_prompt

load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')

# Configure CORS
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
allowed_origins = [
    'http://localhost:5000',
    'http://localhost:3000',
    'https://prompt-validator.onrender.com',
    FRONTEND_URL
]

CORS(app, resources={r"/*": {"origins": allowed_origins}}, supports_credentials=True)

# Folder structure for analysis results
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), 'validation_results')
CRITICAL_FOLDER = os.path.join(RESULTS_FOLDER, 'critical')
HIGH_FOLDER = os.path.join(RESULTS_FOLDER, 'high')
MEDIUM_FOLDER = os.path.join(RESULTS_FOLDER, 'medium')
LOW_FOLDER = os.path.join(RESULTS_FOLDER, 'low')

for folder in [CRITICAL_FOLDER, HIGH_FOLDER, MEDIUM_FOLDER, LOW_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Initialize detector
detector = PromptInjectionDetector()

MAX_PROMPT_LENGTH = 10000


def generate_prompt_id(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


def save_analysis(analysis_result: dict) -> str:
    prompt_id = generate_prompt_id(analysis_result['prompt'])
    risk_level = analysis_result['overall_risk_level']

    # Determine folder based on risk level
    folder_map = {
        'critical': CRITICAL_FOLDER,
        'high': HIGH_FOLDER,
        'medium': MEDIUM_FOLDER,
        'low': LOW_FOLDER
    }

    folder = folder_map.get(risk_level, LOW_FOLDER)
    result_file = os.path.join(folder, f'{prompt_id}.json')

    # Add metadata
    analysis_result['id'] = prompt_id
    analysis_result['timestamp'] = datetime.utcnow().isoformat()
    analysis_result['risk_folder'] = risk_level

    with open(result_file, 'w') as f:
        json.dump(analysis_result, f, indent=2)

    return prompt_id


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'Red Teaming Prompt Validator',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/validate', methods=['POST'])
def validate_prompt():
    """
    Validate a prompt for injection vulnerabilities.
    Expected JSON body: {"prompt": "your prompt here"}
    """
    if not request.json or 'prompt' not in request.json:
        return jsonify({'error': 'No prompt provided in request body'}), 400

    prompt = request.json.get('prompt', '').strip()

    if not prompt:
        return jsonify({'error': 'Prompt cannot be empty'}), 400

    if len(prompt) > MAX_PROMPT_LENGTH:
        return jsonify({
            'error': f'Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters'
        }), 400

    try:
        # Generate analysis report
        report = detector.generate_report(prompt)

        # Save to appropriate folder
        prompt_id = save_analysis(report)

        return jsonify({
            'id': prompt_id,
            'timestamp': datetime.utcnow().isoformat(),
            **report
        }), 200
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/harden', methods=['POST'])
def harden():
    """Suggest fixes and a hardened version of a system prompt. Body: {"prompt": "..."}"""
    prompt = request.json['prompt'].strip()
    return jsonify(harden_prompt(prompt)), 200


@app.route('/analyze', methods=['POST'])
def analyze_prompt():
    """Alias for /validate endpoint"""
    return validate_prompt()


@app.route('/result/<prompt_id>', methods=['GET'])
def get_result(prompt_id):
    """Retrieve a previous analysis result"""
    prompt_id = secure_filename(prompt_id)

    # Search in all risk folders
    for folder in [CRITICAL_FOLDER, HIGH_FOLDER, MEDIUM_FOLDER, LOW_FOLDER]:
        result_file = os.path.join(folder, f'{prompt_id}.json')
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                return jsonify(json.load(f)), 200

    return jsonify({'error': 'Result not found'}), 404


@app.route('/results', methods=['GET'])
def list_results():
    """List all analysis results grouped by risk level"""
    results = {'critical': [], 'high': [], 'medium': [], 'low': []}

    folder_map = {
        'critical': CRITICAL_FOLDER,
        'high': HIGH_FOLDER,
        'medium': MEDIUM_FOLDER,
        'low': LOW_FOLDER
    }

    for risk_level, folder in folder_map.items():
        for file in os.listdir(folder):
            if file.endswith('.json'):
                with open(os.path.join(folder, file), 'r') as f:
                    data = json.load(f)
                    results[risk_level].append({
                        'id': data['id'],
                        'timestamp': data['timestamp'],
                        'risk_score': data['risk_score'],
                        'vulnerability_count': data['vulnerability_count'],
                        'summary': data['summary']
                    })

    return jsonify(results), 200


@app.route('/delete/<prompt_id>', methods=['DELETE'])
def delete_result(prompt_id):
    """Delete an analysis result"""
    prompt_id = secure_filename(prompt_id)

    for folder in [CRITICAL_FOLDER, HIGH_FOLDER, MEDIUM_FOLDER, LOW_FOLDER]:
        result_file = os.path.join(folder, f'{prompt_id}.json')
        if os.path.exists(result_file):
            try:
                os.remove(result_file)
                return jsonify({'message': 'Analysis deleted successfully'}), 200
            except Exception as e:
                return jsonify({'error': f'Failed to delete: {str(e)}'}), 500

    return jsonify({'error': 'Result not found'}), 404


@app.route('/batch-validate', methods=['POST'])
def batch_validate():
    """
    Validate multiple prompts at once.
    Expected JSON body: {"prompts": ["prompt1", "prompt2", ...]}
    """
    if not request.json or 'prompts' not in request.json:
        return jsonify({'error': 'No prompts provided'}), 400

    prompts = request.json.get('prompts', [])

    if not isinstance(prompts, list):
        return jsonify({'error': 'Prompts must be a list'}), 400

    if len(prompts) > 50:
        return jsonify({'error': 'Maximum 50 prompts per batch'}), 400

    results = []
    for prompt in prompts:
        if isinstance(prompt, str) and prompt.strip():
            report = detector.generate_report(prompt.strip())
            prompt_id = save_analysis(report)
            results.append({
                'id': prompt_id,
                **report
            })

    return jsonify({'results': results}), 200


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get statistics about all analyses"""
    stats = {
        'total': 0,
        'by_risk_level': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'total_vulnerabilities': 0,
        'average_risk_score': 0.0
    }

    all_risk_scores = []

    for risk_level in ['critical', 'high', 'medium', 'low']:
        folder_map = {
            'critical': CRITICAL_FOLDER,
            'high': HIGH_FOLDER,
            'medium': MEDIUM_FOLDER,
            'low': LOW_FOLDER
        }
        folder = folder_map[risk_level]

        for file in os.listdir(folder):
            if file.endswith('.json'):
                with open(os.path.join(folder, file), 'r') as f:
                    data = json.load(f)
                    stats['total'] += 1
                    stats['by_risk_level'][risk_level] += 1
                    stats['total_vulnerabilities'] += data['vulnerability_count']
                    all_risk_scores.append(data['risk_score'])

    if all_risk_scores:
        stats['average_risk_score'] = round(sum(all_risk_scores) / len(all_risk_scores), 2)

    return jsonify(stats), 200


@app.route('/')
def index():
    """Serve the main web interface"""
    with open('index.html', 'r') as f:
        return f.read()


@app.route('/api/info', methods=['GET'])
def api_info():
    """Get API information and available endpoints"""
    return jsonify({
        'service': 'Red Teaming Prompt Validator',
        'version': '1.0.0',
        'endpoints': {
            'POST /validate': 'Validate a single prompt for injection vulnerabilities',
            'POST /analyze': 'Alias for /validate',
            'POST /harden': 'Suggest fixes and a hardened version of a system prompt',
            'POST /batch-validate': 'Validate multiple prompts (up to 50)',
            'GET /result/<id>': 'Retrieve a previous analysis result',
            'GET /results': 'List all analysis results by risk level',
            'GET /stats': 'Get statistics about all analyses',
            'DELETE /delete/<id>': 'Delete an analysis result',
            'GET /health': 'Health check endpoint'
        }
    }), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
