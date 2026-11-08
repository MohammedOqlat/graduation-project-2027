# main.py  -  Detection service (FastAPI)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from detector import detect

app = FastAPI(title="SCANIX Detection")


class ScanRequest(BaseModel):
    code: str
    language: str = "python"


@app.post("/detect")
def scan(request: ScanRequest):
    if not request.code.strip():
        raise HTTPException(status_code=422, detail="Code is empty")
    try:
        findings = detect(request.code, request.language)
    except SyntaxError as error:
        raise HTTPException(status_code=422, detail="Invalid Python code: " + str(error))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    return {"language": request.language, "total": len(findings), "findings": findings}
