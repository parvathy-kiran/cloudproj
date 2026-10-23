import os
import io
import json
import time
import hmac
import hashlib
import logging
import qrcode
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Academic Credential Verification Engine", version="v1")

# --- Configurations & Environment Flags ---
USE_LOCAL_STORAGE = os.getenv("USE_LOCAL_STORAGE", "true").lower() == "true"
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "academic-credentials-vault-2026")
SECRET_SIGNING_KEY = os.getenv("SECRET_SIGNING_KEY", "super-secret-university-signing-key").encode('utf-8')
API_DOMAIN = os.getenv("API_DOMAIN", "localhost:8000")

# Local storage fallback directory
LOCAL_STORAGE_DIR = "/app/storage" if os.path.exists("/app") else "./app/storage"
os.makedirs(LOCAL_STORAGE_DIR, exist_ok=True)

# --- AWS S3 Client Conditional Initialization ---
s3_client = None
if not USE_LOCAL_STORAGE:
    import boto3
    s3_client = boto3.client('s3', region_name='us-east-1')

# --- Append-Only Cryptographic Log Configuration ---
LEDGER_PATH = "/app/ledger.log" if os.path.exists("/app") else "./app/ledger.log"
logging.basicConfig(
    filename=LEDGER_PATH,
    level=logging.INFO,
    format="%(message)s"
)

def compute_sha256(file_bytes: bytes) -> str:
    """Computes structural SHA-256 fingerprint of the file."""
    return hashlib.sha256(file_bytes).hexdigest()

def generate_signature(doc_hash: str, credential_id: str) -> str:
    """Generates a secure HMAC digital signature validating structural integrity."""
    message = f"{credential_id}:{doc_hash}".encode('utf-8')
    return hmac.new(SECRET_SIGNING_KEY, message, hashlib.sha256).hexdigest()

def save_file(file_bytes: io.BytesIO, s3_path: str, local_filename: str, content_type: str):
    """Helper to route storage to S3 or Local Disk seamlessly."""
    if USE_LOCAL_STORAGE:
        local_path = os.path.join(LOCAL_STORAGE_DIR, local_filename)
        with open(local_path, "wb") as f:
            f.write(file_bytes.getvalue())
        return f"file://{local_path}"
    else:
        s3_client.upload_fileobj(
            file_bytes,
            S3_BUCKET_NAME,
            s3_path,
            ExtraArgs={'ContentType': content_type}
        )
        return f"s3://{S3_BUCKET_NAME}/{s3_path}"

# --- API ENDPOINTS ---

@app.post("/api/v1/credential/issue", status_code=status.HTTP_201_CREATED)
async def issue_credential(credential_id: str, file: UploadFile = File(...)):
    """
    Computes hashes, generates digital signatures, updates the ledger,
    and returns a matrix QR code payload.
    """
    try:
        file_bytes = await file.read()
        doc_hash = compute_sha256(file_bytes)
        digital_signature = generate_signature(doc_hash, credential_id)
        
        # 1. Update the Local Append-Only Ledger (Structured JSON Log Entry)
        log_entry = {
            "credential_id": credential_id,
            "document_hash": doc_hash,
            "signature": digital_signature,
            "timestamp": time.time()
        }
        logging.info(json.dumps(log_entry))
        
        # 2. Store Raw PDF File (Local or S3)
        pdf_stream = io.BytesIO(file_bytes)
        pdf_uri = save_file(
            file_bytes=pdf_stream,
            s3_path=f"credentials/{credential_id}.pdf",
            local_filename=f"{credential_id}.pdf",
            content_type='application/pdf'
        )
        
        # 3. Dynamic Matrix QR Code Generation
        verification_url = f"http://{API_DOMAIN}/api/v1/credential/verify/{credential_id}?hash={doc_hash}"
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(verification_url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_bytes_io = io.BytesIO()
        qr_img.save(qr_bytes_io, format='PNG')
        qr_bytes_io.seek(0)
        
        # 4. Store Matrix QR Image (Local or S3)
        qr_uri = save_file(
            file_bytes=qr_bytes_io,
            s3_path=f"qr_codes/{credential_id}_qr.png",
            local_filename=f"{credential_id}_qr.png",
            content_type='image/png'
        )
        
        return {
            "status": "Success",
            "credential_id": credential_id,
            "sha256_hash": doc_hash,
            "signature": digital_signature,
            "verification_url": verification_url,
            "storage_mode": "local" if USE_LOCAL_STORAGE else "s3",
            "pdf_uri": pdf_uri,
            "qr_uri": qr_uri
        }
        
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/v1/credential/verify/{credential_id}")
async def verify_credential(credential_id: str, hash: str):
    """
    Fetches historical record from the ledger, re-computes structural signatures,
    and returns instant validation results (Target latency: ~0.12s).
    """
    start_time = time.time()
    
    # 1. Fetch matching records from the append-only ledger file
    ledger_record = None
    if os.path.exists(LEDGER_PATH):
        with open(LEDGER_PATH, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if record.get("credential_id") == credential_id:
                        ledger_record = record  # Grab latest entry
                except json.JSONDecodeError:
                    continue

    if not ledger_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Credential metadata not found in system ledger."
        )
    
    # 2. Re-compute digital signature based on incoming query parameters
    expected_signature = generate_signature(hash, credential_id)
    execution_time = round(time.time() - start_time, 4)
    
    # 3. Validate Structural Integrity and State Consistency
    if (ledger_record["document_hash"] == hash) and (ledger_record["signature"] == expected_signature):
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "Valid",
                "message": "Structural hash and signature match ledger state.",
                "execution_time_seconds": execution_time,
                "data": {
                    "credential_id": credential_id,
                    "verified_hash": hash,
                    "issued_at": ledger_record["timestamp"]
                }
            }
        )
    
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "status": "Tampered",
            "message": "Mismatched document hash indicates record corruption or forgery.",
            "execution_time_seconds": execution_time,
            "mismatch_detected": {
                "provided_hash": hash,
                "ledger_stored_hash": ledger_record["document_hash"]
            }
        }
    )
