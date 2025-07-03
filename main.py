from fastapi import FastAPI, Query
from samp_query import query_samp
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/")
def home():
    return {"message": "SA-MP Query API by Railway"}

@app.get("/query")
def query(host: str = Query(...), port: int = 7777):
    result_data = {}

    def handle_response(error, data):
        nonlocal result_data
        if error:
            result_data = {"success": False, "error": error}
        else:
            result_data = {"success": True, "data": data}

    query_samp({"host": host, "port": port, "timeout": 1000}, handle_response)
    return JSONResponse(result_data)
