import uuid
import tempfile
import os
from runner import start_nmap
from parser import parse_xml

JOBS = {} # estructura temporal que actua como bbdd de escaneos

def create_job(target, profile): # se encarga de poner en marcha el flujo del análisis
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
    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
    finally:
        if os.path.exists(xml_outfile):
            os.remove(xml_outfile)
            
    return job

def get_job(scan_id): # busca y recupera del diccionario JOBS los escaneos
    return JOBS.get(scan_id)

def public(job): # devuelve una versión filtrada del diccionario en 1 unico job
    if job is None:
        return None
    return {
        "scan_id": job["scan_id"],
        "target": job["target"],
        "profile": job["profile"],
        "status": job["status"],
        "events": job.get("events", [])
    }