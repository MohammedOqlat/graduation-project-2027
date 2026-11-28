# main.py
# ------------------------------------------------------------
# SCANIX - Part 3 (Remediation) - the WEB SERVICE file.
#
# What this file does:
#   - Starts a FastAPI web server on port 8003.
#   - POST /remediate  receives the code (and optionally the findings from Detection),
#     fixes what it can, re-scans the fixed code with Detection, and returns the result.
#
# Detection (port 8001) must be running, because the re-scan calls it.
#
# How to run (from inside the remediation folder):
#       python main.py
# Then open the test page:  http://127.0.0.1:8003/docs
# ------------------------------------------------------------

from typing import List, Optional      # type names for the optional "findings" list

import httpx                           # we catch its errors when Detection is not reachable
import uvicorn                         # the server that runs FastAPI
from fastapi import FastAPI, HTTPException   # the framework, and the error we send back to the user
from pydantic import BaseModel         # describes the JSON body that the endpoint accepts

from remediator import remediate       # the main logic from remediator.py

app = FastAPI(title="SCANIX Remediation")   # create the application


class RemediateRequest(BaseModel):
    """The JSON body of POST /remediate."""
    code: str                                  # the source code to fix
    language: str = "python"                   # only "python" is supported for now
    findings: Optional[List[dict]] = None      # the findings from Detection; if missing we ask Detection ourselves


@app.post("/remediate")                        # POST http://127.0.0.1:8003/remediate
def remediate_code(request: RemediateRequest):
    if not request.code.strip():               # empty code: nothing to fix
        raise HTTPException(status_code=422, detail="Code is empty")
    if request.language != "python":           # same limit as the Detection part
        raise HTTPException(status_code=422, detail="Only 'python' is supported for now")
    try:
        return remediate(request.code, request.findings)
    except SyntaxError as error:               # the code is not valid Python
        raise HTTPException(status_code=422, detail="Invalid Python code: " + str(error))
    except httpx.HTTPError as error:           # Detection is down or answered with an error
        raise HTTPException(
            status_code=502,
            detail="Could not reach the Detection service (is it running on port 8001?): " + str(error),
        )


# ---------- Run the server ----------
if __name__ == "__main__":                     # true only when we run "python main.py"
    uvicorn.run(app, host="127.0.0.1", port=8003)   # start the server on port 8003
