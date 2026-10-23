# -----------------------------------------------------------------------------
# Décisions de l'analyste et seuils du Quality Gate.
#
# Deux tables créées automatiquement au démarrage de l'API (comme builds_jenkins) :
#   - decisions_findings : journal des décisions manuelles (qui, quand, pourquoi).
#   - seuils_quality_gate : seuils de tolérance propres à chaque projet.
# -----------------------------------------------------------------------------

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class FindingDecision(Base):
    __tablename__ = "decisions_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilites.id"), nullable=False)
    decided_by: Mapped[int | None] = mapped_column(
        ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True
    )
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class QualityGateSetting(Base):
    __tablename__ = "seuils_quality_gate"

    project_id: Mapped[int] = mapped_column(ForeignKey("projets.id"), primary_key=True)
    max_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_high: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    updated_by: Mapped[int | None] = mapped_column(
        ForeignKey("utilisateurs.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
