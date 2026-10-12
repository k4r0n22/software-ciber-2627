import uuid
import tempfile
import os
import requests
from runner import start_nmap
from parser import parse_xml

JOBS = {}  # estructura temporal que actua como bbdd de escaneos
SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8005/events")  # URL del SIEM o su mock (temporal para pruebas)

def publish_events_to_siem(events):
    """Envía los hallazgos en formato común mediante POST /events hacia el SIEM."""
    for event in events:
        try:
            requests.post(SIEM_URL, json=event, timeout=3)
        except requests.exceptions.RequestException:
            # Si el SIEM no está disponible, evitamos que rompa el flujo del escaneo
            pass

def create_job(target, profile):  # se encarga de poner en marcha el flujo del análisis
    scan_id = str(uuid.uuid4())
    
    fd, xml_outfile = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    
    job = {
        "scan_id": scan_id,
        "target": target,
        "profile": profile,
        "status": "running",
        "events": []
    }
    JOBS[scan_id] = job

    try:
        # Ejecución síncrona: esperamos a que Nmap termine
        proc = start_nmap(target, profile, xml_outfile)
        proc.wait()
        
        if os.path.exists(xml_outfile):
            with open(xml_outfile, "r", encoding="utf-8") as f:
                xml_content = f.read()
            job["events"] = parse_xml(xml_content, scan_id, profile)
        
        job["status"] = "completed"
        
        # Publicamos los eventos automáticamente al SIEM tras completarse
        publish_events_to_siem(job["events"])

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
    finally:
        if os.path.exists(xml_outfile):
            os.remove(xml_outfile)
            
    # Aseguramos que el estado final quede actualizado en el diccionario global
    JOBS[scan_id] = job
    return job

def get_job(scan_id):  # busca y recupera del diccionario JOBS los escaneos
    return JOBS.get(scan_id)

def public(job):  # devuelve una versión filtrada del diccionario en 1 unico job
    if job is None:
        return None
    return {
        "scan_id": job["scan_id"],
        "target": job["target"],
        "profile": job["profile"],
        "status": job["status"],
        "events": job.get("events", [])
    }