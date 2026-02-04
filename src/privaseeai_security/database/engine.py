"""
Async database engine and session management for PostgreSQL with asyncpg.

Uses SQLAlchemy 2.0 async patterns with proper connection pooling.
"""

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base

# Default database URL (override with DATABASE_URL environment variable)
DEFAULT_DATABASE_URL = "postgresql+asyncpg://privasee:privasee@localhost:5432/privasee_security"


def get_database_url() -> str:
    """
    Get database URL from environment or use default.

    Returns:
        Database URL string for asyncpg connection
    """
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def create_engine(database_url: str | None = None, echo: bool = False) -> AsyncEngine:
    """
    Create async SQLAlchemy engine with asyncpg driver.

    Args:
        database_url: PostgreSQL connection URL. If None, uses environment or default.
        echo: Whether to echo SQL statements (useful for debugging)

    Returns:
        Configured AsyncEngine instance
    """
    url = database_url or get_database_url()

    return create_async_engine(
        url,
        echo=echo,
        pool_pre_ping=True,  # Verify connections before using
        pool_size=20,  # Connection pool size
        max_overflow=10,  # Allow up to 10 additional connections
        pool_recycle=3600,  # Recycle connections after 1 hour
    )


# Global engine instance (initialize once)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(echo: bool = False) -> AsyncEngine:
    """
    Get or create the global async engine instance.

    Args:
        echo: Whether to echo SQL statements

    Returns:
        Global AsyncEngine instance
    """
    global _engine
    if _engine is None:
        _engine = create_engine(echo=echo)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """
    Get or create the global session factory.

    Returns:
        Session factory for creating async sessions
    """
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,  # Don't expire objects after commit
            autocommit=False,
            autoflush=False,
        )
    return _session_factory


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI or other frameworks to get async database sessions.

    Yields:
        AsyncSession instance

    Example:
        ```python
        async def my_route(session: AsyncSession = Depends(get_async_session)):
            result = await session.execute(select(Device))
            devices = result.scalars().all()
        ```
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db(drop_existing: bool = False) -> None:
    """
    Initialize database schema.

    Creates all tables defined in Base metadata. For TimescaleDB hypertables,
    you should run alembic migrations after this to set up partitioning.

    Args:
        drop_existing: If True, drops all existing tables first (DANGEROUS!)

    Warning:
        This does NOT create TimescaleDB hypertables. Use alembic migrations
        for production deployments with proper hypertable setup.
    """
    engine = get_engine()

    async with engine.begin() as conn:
        if drop_existing:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """
    Dispose of the global engine and close all connections.

    Call this when shutting down the application.
    """
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
