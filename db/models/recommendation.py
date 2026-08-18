from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from db.models import Base


class SecurityRecommendation(Base):
    """security recommendations from lynis/hardening checks"""

    __tablename__ = "security_recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    test_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    field_name: Mapped[str | None] = mapped_column(String(200))
    expected_value: Mapped[str | None] = mapped_column(Text)
    actual_value: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(String(50), index=True)
    severity: Mapped[str | None] = mapped_column(String(50), index=True)
    source: Mapped[str | None] = mapped_column(String(100))
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(UTC)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "test_id": self.test_id,
            "category": self.category,
            "description": self.description,
            "field_name": self.field_name,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "status": self.status,
            "severity": self.severity,
            "source": self.source,
            "raw_data": self.raw_data or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
