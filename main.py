"""FastAPI entrypoint for the local privacy access gateway."""
from __future__ import annotations

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from app.api import register_error_handlers, register_routes
from app.deps import shutdown_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    shutdown_service()


def create_app() -> FastAPI:
    app = FastAPI(title="Local Privacy Access Gateway", lifespan=lifespan)
    app.include_router(register_routes())
    register_error_handlers(app)
    return app


app = create_app()


@app.get("/")
def read_root() -> dict:
    return {"service": "privacy-access-gateway", "status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
