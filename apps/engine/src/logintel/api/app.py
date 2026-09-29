"""FastAPI application factory with lifespan lifecycle hooks."""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from logintel.api.routes import router
from logintel.config import settings
from logintel.ingestion import ingestion_engine
from logintel.logging import get_logger, setup_logging
from logintel.storage import db

logger = get_logger("api.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup logging and database
    setup_logging(log_file=settings.log_file, level=settings.log_level)
    logger.info("Starting LogIntel Engine version %s...", settings.version)
    
    # Initialize DB & migrations
    db.initialize()

    # Start live telemetry ingestion
    ingestion_engine.start()

    yield

    # Teardown
    logger.info("Shutting down LogIntel Engine...")
    ingestion_engine.stop()
    db.close()
    logger.info("LogIntel Engine shutdown complete.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="LogIntel Security Telemetry Engine",
        version=settings.version,
        lifespan=lifespan,
    )

    # Permit local frontend origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "tauri://localhost",
            "http://localhost:41721",
            "http://127.0.0.1:41721",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
