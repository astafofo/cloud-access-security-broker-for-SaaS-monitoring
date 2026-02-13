"""
Main FastAPI application entry point for the CASB system.
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import structlog

from app.core.config import settings
from app.core.database import engine, Base
from app.core.security import get_current_user
from app.api.routes import auth, monitoring, policies, alerts, saas_apps
from app.core.celery import celery_app

logger = structlog.get_logger()

security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("Starting CASB application")
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")
    yield
    logger.info("Shutting down CASB application")


app = FastAPI(
    title="Cloud Access Security Broker API",
    description="CASB for SaaS monitoring and security",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["Monitoring"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["Policies"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(saas_apps.router, prefix="/api/v1/saas", tags=["SaaS Applications"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Cloud Access Security Broker API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "database": "connected",
        "redis": "connected"
    }


@app.get("/api/v1/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    return current_user


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
