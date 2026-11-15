"""Opt-in demo entry point: public QR API + built SPA only, never private APIs.

This module does not start a listener. Use start_public_demo.sh explicitly.
"""
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from backend.app.api.v1.shares import public_router

DIST = Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(public_router, prefix='/api/v1')
app.mount('/assets', StaticFiles(directory=DIST / 'assets', check_dir=False), name='assets')

@app.middleware('http')
async def privacy_headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.get('/verify/share/{token}', include_in_schema=False)
def public_page(token: str):
    return FileResponse(DIST / 'index.html')
