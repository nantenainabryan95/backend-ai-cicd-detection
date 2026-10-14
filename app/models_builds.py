# -----------------------------------------------------------------------------
# Table "builds_jenkins" : une ligne par build Jenkins et par projet.
#
# Pourquoi une table à part ? Un finding connu garde seulement le DERNIER build
# qui l'a vu (dédoublonnage). Pour l'historique ("que donnait le build 10 ?"),
# on enregistre donc un instantané à la fin de chaque build : nombre de
# vulnérabilités par sévérité + résultat du Quality Gate.
# -----------------------------------------------------------------------------

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class BuildRun(Base):
    __tablename__ = "builds_jenkins"
    __table_args__ = (
        UniqueConstraint("project_id", "build_number", name="uq_build_project_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    project_id: Mapped[int] = mapped_column(ForeignKey("projets.id"), nullable=False)
    build_number: Mapped[int] = mapped_column(Integer, nullable=False)
    git_commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # Vulnérabilités OUVERTES (non corrigées, ni faux positif, ni risque accepté)
    # vues lors de ce build, par sévérité.
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)

    # Nombre de vulnérabilités qui ont fait échouer le gate, et verdict.
    blocking: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
