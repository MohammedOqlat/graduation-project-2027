# main.py
from fastapi import FastAPI, HTTPException
from analyzer import analyze_finding

app = FastAPI()


@app.post("/analyze")
def analyze(finding: dict):
    # A finding must at least have an id and a type
    if "id" not in finding or "type" not in finding:
        raise HTTPException(
            status_code=422,
            detail="Finding must contain 'id' and 'type'",
        )
    return analyze_finding(finding)