from flask import Flask, jsonify, request
from runner import get_profiles
from jobs import create_job, get_job, public, JOBS

app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    profile = data.get("profile", "vuln")
    if not target:
        return jsonify({"error": "falta 'target'"}), 400
    if profile not in get_profiles():
        return jsonify({"error": f"perfil no válido: {get_profiles()}"}), 400

    scan_id = create_job(target, profile)
    return jsonify({"scan_id": scan_id, "status": "running"}), 202


@app.route("/scan/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    job = get_job(scan_id)
    if job is None:
        return jsonify({"error": "scan no encontrado"}), 404
    return jsonify(public(job))


@app.route("/history", methods=["GET"])
def history():
    result = []
    for scan_id in JOBS:
        j = public(get_job(scan_id))   # refresca el estado de cada uno
        j.pop("events")
        result.append(j)
    return jsonify(result)


@app.route("/diff", methods=["GET"])
def diff():
    return jsonify({})  # TODO


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)