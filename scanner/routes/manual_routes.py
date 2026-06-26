from flask import Blueprint, request, jsonify
from scanner.security.enterprise_auth import require_api_key

manual_bp = Blueprint('manual', __name__, url_prefix='/api/manual')

@manual_bp.route('/replay', methods=['POST'])
@require_api_key()
def manual_replay():
    # Move your manual_replay_request logic here
    return jsonify({"status": "replayed"})

@manual_bp.route('/compare-responses', methods=['POST'])
@require_api_key()
def compare_responses():
    # Move your manual_compare_responses logic here
    return jsonify({"status": "compared"})
