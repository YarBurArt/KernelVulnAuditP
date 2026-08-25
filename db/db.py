from db.interfaces import ThreatDB


def get_db(backend: str = "orm") -> ThreatDB:
    """
    Create a ThreatDB instance for the requested backend.
    backend:
        "orm"    - SQLAlchemy via db_orm.ThreatIntelligenceORM, kwargs: db_url
        "memory" - in-memory via db_rd.InMemoryThreatDB, kwargs: none
    """
    if backend == "orm":
        from db.db_orm import ThreatIntelligenceORM

        return ThreatIntelligenceORM(db_url="sqlite:///ti.db")
    elif backend == "memory":
        from db.db_rd import InMemoryThreatDB

        return InMemoryThreatDB()
    else:
        raise ValueError(
            f"Unknown backend: {backend!r}. Use 'orm' or 'memory'."
        )
