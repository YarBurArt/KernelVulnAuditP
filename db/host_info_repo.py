import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from core.entities import HostInfo
from db.mappers import build_host_model, query_host_with_children, to_data
from db.models import HostInfo as HostInfoRow

logger = logging.getLogger(f"kernel_audit.{__name__}")


class HostInfoRepository:
    """repository for host environment snapshots."""

    def __init__(self, session_factory: sessionmaker[Session]):
        self._session_factory = session_factory

    def get_session(self) -> Session:
        return self._session_factory()

    def add_host_info(self, host_data: HostInfo) -> HostInfoRow:
        session = self.get_session()
        try:
            host = build_host_model(session, host_data)
            session.commit()
            session.refresh(host)
            logger.info("host info snapshot %d added to TI DB", host.id)
            logger.debug("host info snapshot %d added to TI DB: %s", host.id, host)
            return host
        except SQLAlchemyError as e:
            session.rollback()
            logger.error("adding host info snapshot failed: %s", e)
            raise
        finally:
            session.close()

    def get_host_info(self, host_info_id: int) -> HostInfo | None:
        session = self.get_session()
        try:
            host = (
                query_host_with_children(session)
                .filter_by(id=host_info_id)
                .first()
            )
            if host is None:
                logger.debug("host info %d not found in TI DB", host_info_id)
                return None
            return to_data(host)
        finally:
            session.close()

    def get_latest_host_info(self) -> HostInfo | None:
        session = self.get_session()
        try:
            host = (
                query_host_with_children(session)
                .order_by(HostInfoRow.captured_at.desc(), HostInfoRow.id.desc())
                .first()
            )
            if host is None:
                logger.debug("no host info snapshots in TI DB")
                return None
            return to_data(host)
        finally:
            session.close()

    def get_host_infos(
        self, limit: int = 100, offset: int = 0
    ) -> list[HostInfo]:
        session = self.get_session()
        try:
            hosts = (
                session.query(HostInfoRow)
                .order_by(HostInfoRow.captured_at.desc(), HostInfoRow.id.desc())
                .limit(limit)
                .offset(offset)
                .all()
            )
            return [to_data(h, include_children=False) for h in hosts]
        finally:
            session.close()