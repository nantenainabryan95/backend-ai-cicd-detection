# -----------------------------------------------------------------------------
# Ce fichier définit les TABLES de la base de données, écrites comme des
# classes Python (principe d'un ORM : SQLAlchemy).
# -----------------------------------------------------------------------------

import enum
from datetime import datetime

from sqlalchemy import String, Text, Integer, Float, Boolean, ForeignKey, Enum, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# -----------------------------------------------------------------------------
# Énumérations : listent les seules valeurs possibles d'un champ.
# -----------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    DEVELOPER = "developer"
    APPSEC = "appsec"
    TECH_LEAD = "tech_lead"
    ADMIN = "admin"


class FindingStatus(str, enum.Enum):
    """Cycle de vie global du finding, du côté remédiation."""
    NEW = "new"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FindingSeverity(str, enum.Enum):
    """Sévérité calculée par NOTRE moteur de scoring (règles CVSS/EPSS/KEV)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AIVerdict(str, enum.Enum):
    """Le verdict du LLM : confirme-t-il que c'est une vraie menace ?"""
    VRAIE_MENACE = "vraie_menace"
    FAUX_POSITIF = "faux_positif"
    INCERTAIN = "incertain"


class AIAdjustedPriority(str, enum.Enum):
    """La priorité telle que réévaluée par le LLM, après lecture du contexte."""
    BASSE = "basse"
    MOYENNE = "moyenne"
    ELEVEE = "elevee"
    CRITIQUE_CONFIRMEE = "critique_confirmee"


class HumanReviewStatus(str, enum.Enum):
    """Validation humaine du verdict de l'IA (Human-in-the-Loop)."""
    EN_ATTENTE = "en_attente"
    APPROUVE = "approuve"
    REJETE = "rejete"


# -----------------------------------------------------------------------------
# Table "utilisateurs"
# -----------------------------------------------------------------------------

class User(Base):
    __tablename__ = "utilisateurs"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.DEVELOPER)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


# -----------------------------------------------------------------------------
# Table "projets"
# -----------------------------------------------------------------------------

class Project(Base):
    __tablename__ = "projets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repository_url: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    findings: Mapped[list["Finding"]] = relationship(back_populates="project")

    def __repr__(self) -> str:
        return f"<Project {self.name}>"


# -----------------------------------------------------------------------------
# Table "vulnerabilites" — ce que les scanners ont trouvé, dans quel contexte
# CI/CD (build Jenkins, commit Git) exactement.
# -----------------------------------------------------------------------------

class Finding(Base):
    __tablename__ = "vulnerabilites"

    id: Mapped[int] = mapped_column(primary_key=True)

    project_id: Mapped[int] = mapped_column(ForeignKey("projets.id"), nullable=False)
    project: Mapped["Project"] = relationship(back_populates="findings")

    # --- Traçabilité CI/CD : d'où vient exactement ce finding ---
    jenkins_build_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    git_commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # --- Ce que le scanner a trouvé, précisément ---
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    scanner_name: Mapped[str] = mapped_column(String(100))          # "trivy", "semgrep", "gitleaks"...
    vulnerability_id: Mapped[str | None] = mapped_column(String(100), nullable=True)  # CVE-xxxx ou règle Semgrep
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)  # label brut du scanner (LOW/HIGH...)

    # --- Éléments servant au calcul du score par NOTRE moteur de priorisation ---
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    is_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # --- Résultat de NOTRE moteur (règles, pas le LLM) ---
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0 à 100
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), default=FindingSeverity.MEDIUM)

    # --- Cycle de vie / remédiation ---
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.NEW)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="AIAnalysis.created_at.desc()"
    )

    def __repr__(self) -> str:
        return f"<Finding {self.title} — score {self.priority_score}>"


# -----------------------------------------------------------------------------
# Table "analyses_ia" — historique des analyses du LLM sur chaque finding,
# et validation humaine de ces analyses (Human-in-the-Loop).
# -----------------------------------------------------------------------------

class AIAnalysis(Base):
    __tablename__ = "analyses_ia"

    id: Mapped[int] = mapped_column(primary_key=True)

    finding_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilites.id"), nullable=False)
    finding: Mapped["Finding"] = relationship(back_populates="ai_analyses")

    # --- Traçabilité du modèle utilisé ---
    llm_provider: Mapped[str] = mapped_column(String(50))    # "anthropic", "ollama"...
    ai_model_name: Mapped[str] = mapped_column(String(100))  # "claude-sonnet-4-6", "deepseek-coder:7b"...

    # --- Verdict et raisonnement du LLM ---
    ai_verdict: Mapped[AIVerdict] = mapped_column(Enum(AIVerdict), default=AIVerdict.INCERTAIN)
    ai_adjusted_priority: Mapped[AIAdjustedPriority | None] = mapped_column(Enum(AIAdjustedPriority), nullable=True)
    ai_reasoning: Mapped[str] = mapped_column(Text)                       # explication en langage clair
    ai_suggested_fix: Mapped[str | None] = mapped_column(Text, nullable=True)  # correctif proposé

    # --- Validation humaine du verdict de l'IA ---
    human_status: Mapped[HumanReviewStatus] = mapped_column(Enum(HumanReviewStatus), default=HumanReviewStatus.EN_ATTENTE)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("utilisateurs.id"), nullable=True)
    reviewer: Mapped["User | None"] = relationship()

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<AIAnalysis finding_id={self.finding_id} verdict={self.ai_verdict}>"
