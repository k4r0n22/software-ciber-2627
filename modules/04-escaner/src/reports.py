from flask import Blueprint, jsonify

reports_bp = Blueprint("reports", __name__)

# Datos simulados exclusivamente para esta primera prueba.
# Después se sustituirá esta consulta por el almacenamiento real.
INFORMES_SIMULADOS = {
    "scan-001": [
        {
            "event_id": "b52ee782-265f-4ec7-a719-484460628ef9",
            "timestamp": "2026-09-29T10:30:00Z",
            "source": "scanner",
            "event_type": "vulnerability_detected",
            "severity": "medium",
            "title": "Cabecera de seguridad ausente",
            "description": (
                "El servicio HTTP no devuelve X-Content-Type-Options."
            ),
            "details": {
                "target": {
                    "ip": "192.168.56.10",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                },
                "scan_id": "scan-001",
                "tool": "nmap",
                "profile": "web",
                "script_id": "http-headers",
                "evidence": (
                    "X-Content-Type-Options no aparece "
                    "en las cabeceras recibidas."
                ),
                "cve": None,
                "cvss": None,
            },
        }
    ],
    "scan-002": [],
}


@reports_bp.route("/scans/<scan_id>/report", methods=["GET"])
def consultar_informe(scan_id):
    informe = INFORMES_SIMULADOS.get(scan_id)

    if informe is None:
        return jsonify({
            "error": {
                "codigo": "SCAN_NOT_FOUND",
                "mensaje": "No existe un escaneo con ese identificador",
            }
        }), 404

    return jsonify(informe), 200