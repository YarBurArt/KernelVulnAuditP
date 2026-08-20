import logging

from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from core.entities import RecommendationStats, SecurityRecommendation
from db.mappers import entity_write_dict
from db.models import SecurityRecommendation as SecurityRecommendationRow

logger = logging.getLogger(f"kernel_audit.{__name__}")

_REC_COLUMNS = {c.name for c in SecurityRecommendationRow.__table__.columns}


def _rec_entity(r: SecurityRecommendationRow) -> SecurityRecommendation:
    return SecurityRecommendation(
        id=r.id,
        test_id=r.test_id,
        category=r.category,
        description=r.description,
        field_name=r.field_name,
        expected_value=r.expected_value,
        actual_value=r.actual_value,
        status=r.status,
        severity=r.severity,
        source=r.source,
        raw_data=r.raw_data or {},
        created_at=r.created_at,
    )


class RecommendationRepository:
    """repository for security recommendations."""

    def __init__(self, session_factory: sessionmaker[Session]):
        self._session_factory = session_factory

    def get_session(self) -> Session:
        return self._session_factory()

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        """add security recommendation"""
        session = self.get_session()
        try:
            write = {
                k: v
                for k, v in entity_write_dict(rec_data).items()
                if k in _REC_COLUMNS and k != "id"
            }
            rec = SecurityRecommendationRow(**write)
            session.add(rec)
            session.commit()
            session.refresh(rec)
            logger.debug(f"result data: {rec.to_dict()}")
            return rec.id
        except (SQLAlchemyError, ValueError, KeyError, TypeError) as e:
            session.rollback()
            logger.error(e)
            raise
        finally:
            session.close()

    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int:
        """bulk insert security recommendations"""
        count = 0
        for rec in recommendations:
            try:
                self.add_security_recommendation(rec)
                count += 1
            except (SQLAlchemyError, ValueError, KeyError, TypeError) as e:
                logger.warning(f"Error inserting rec {rec.test_id}: {e}")
        return count

    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityRecommendation]:
        """get security recommendations with filters"""
        session = self.get_session()
        try:
            query = session.query(SecurityRecommendationRow)
            if category:
                query = query.filter_by(category=category)
            if status:
                query = query.filter_by(status=status)
            query = query.order_by(
                SecurityRecommendationRow.severity.desc(),
                SecurityRecommendationRow.test_id.asc(),
            )
            results = query.limit(limit).offset(offset).all()
            return [_rec_entity(r) for r in results]
        finally:
            session.close()

    def get_recommendations_stats(self) -> RecommendationStats:
        """get security recommendations statistics"""
        session = self.get_session()
        try:
            total = session.query(SecurityRecommendationRow).count()

            def _counts(column) -> dict[str, int]:
                rows = (
                    session.query(column, func.count(SecurityRecommendationRow.id))
                    .filter(column.isnot(None))
                    .group_by(column)
                    .all()
                )
                return {row[0]: row[1] for row in rows}

            by_category = _counts(SecurityRecommendationRow.category)
            logger.debug(f"Parsed recommendation category stats: {by_category}")
            by_status = _counts(SecurityRecommendationRow.status)
            logger.debug(f"Parsed recommendation status stats: {by_status}")
            by_severity = _counts(SecurityRecommendationRow.severity)
            logger.debug(
                f"Parsed recommendation severity stats: {by_severity}"
            )

            stats = RecommendationStats(
                total=total,
                by_category=by_category,
                by_status=by_status,
                by_severity=by_severity,
            )
            logger.debug(f"recommendations / params stats: {stats}")
            return stats
        finally:
            session.close()