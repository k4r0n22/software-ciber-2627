from flask import Blueprint, jsonify
from jobs import get_job

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/scans/<scan_id>/report", methods=["GET"])
def consultar_informe(scan_id):
    """Consulta los eventos del escaneo guardados en memoria por jobs.py."""
    job = get_job(scan_id)

    if job is None:
        return jsonify({
            "error": {
                "codigo": "SCAN_NOT_FOUND",
                "mensaje": "No existe un escaneo con ese identificador",
            }
        }), 404

    status = job.get("status")
    if status in ("pending", "running"):
        return jsonify({
            "scan_id": scan_id,
            "estado": "pendiente" if status == "pending" else "en_curso",
            "mensaje": "El informe todavía no está disponible",
        }), 202

    # Un fallo o un informe ausente no equivalen a cero hallazgos.
    events = job.get("events")
    if status != "completed" or not isinstance(events, list):
        return jsonify({
            "error": {
                "codigo": "INTERNAL_ERROR",
                "mensaje": "No se pudo recuperar el informe",
            }
        }), 500

    # Conserva los eventos y sus identificadores tal como se envían al SIEM.
    return jsonify(events), 200
