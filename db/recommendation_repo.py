import logging
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from db.models import SecurityRecommendation

logger = logging.getLogger(f"kernel_audit.{__name__}")


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
            session.add(rec_data)
            session.commit()
            session.refresh(rec_data)
            logger.debug(f"result data: {rec_data.to_dict()}")
            return rec_data.id
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
    ) -> list[dict[str, Any]]:
        """get security recommendations with filters"""
        session = self.get_session()
        try:
            query = session.query(SecurityRecommendation)
            if category:
                query = query.filter_by(category=category)
            if status:
                query = query.filter_by(status=status)
            query = query.order_by(
                SecurityRecommendation.severity.desc(),
                SecurityRecommendation.test_id.asc(),
            )
            results = query.limit(limit).offset(offset).all()
            return [r.to_dict() for r in results]
        finally:
            session.close()

    def get_recommendations_stats(self) -> dict[str, Any]:
        """get security recommendations statistics"""
        session = self.get_session()
        try:
            stats: dict[str, Any] = {
                "total": session.query(SecurityRecommendation).count()
            }
            cat_q = (
                session.query(
                    SecurityRecommendation.category,
                    func.count(SecurityRecommendation.id),
                )
                .filter(SecurityRecommendation.category.isnot(None))
                .group_by(SecurityRecommendation.category)
                .all()
            )
            parsed_category = {row[0]: row[1] for row in cat_q}
            stats["by_category"] = parsed_category
            logger.debug(f"Parsed recommendation category stats: {parsed_category}")

            stat_q = (
                session.query(
                    SecurityRecommendation.status,
                    func.count(SecurityRecommendation.id),
                )
                .filter(SecurityRecommendation.status.isnot(None))
                .group_by(SecurityRecommendation.status)
                .all()
            )
            parsed_status = {row[0]: row[1] for row in stat_q}
            stats["by_status"] = parsed_status
            logger.debug(f"Parsed recommendation status stats: {parsed_status}")

            sev_q = (
                session.query(
                    SecurityRecommendation.severity,
                    func.count(SecurityRecommendation.id),
                )
                .filter(SecurityRecommendation.severity.isnot(None))
                .group_by(SecurityRecommendation.severity)
                .all()
            )
            parsed_severity_rec = {row[0]: row[1] for row in sev_q}
            stats["by_severity"] = parsed_severity_rec
            logger.debug(
                f"Parsed recommendation severity stats: {parsed_severity_rec}"
            )

            logger.debug(f"recommendations / params stats: {stats}")
            return stats
        finally:
            session.close()