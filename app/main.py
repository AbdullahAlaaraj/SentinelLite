from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.api.routes import router

app = FastAPI(title="SentinelLite")

app.include_router(router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")