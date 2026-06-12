from __future__ import annotations

import hashlib
import html
import hmac
import os
import re
import secrets
import json
import smtplib
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    text,
    create_engine,
    func,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError


# ==================================================
# CONFIGURAÇÃO PRINCIPAL
# ==================================================

APP_VERSION = "4.2.4-weekly-event-auto-rotation"
DEFAULT_DATABASE_URL = "sqlite:///./database.db"
SAFE_DEV_ADMIN_PASSWORD = "admin123456"
SAFE_DEV_JWT_SECRET = "dev-only-change-this-secret-local-000000000000"
FORBIDDEN_PRODUCTION_SECRETS = {
    "",
    "admin123456",
    "troque-essa-chave-no-render",
    "troque-por-uma-chave-grande-e-secreta",
    SAFE_DEV_JWT_SECRET,
}

APP_ENV = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "development")).strip().casefold() or "development"
IS_PRODUCTION = APP_ENV in {"production", "prod"} or os.getenv("RENDER", "").strip().lower() == "true"


def normalize_database_url(url: str) -> str:
    value = str(url or "").strip()
    # Render/Postgres às vezes usa postgres://. SQLAlchemy prefere postgresql://.
    if value.startswith("postgres://"):
        value = value.replace("postgres://", "postgresql://", 1)
    return value


def require_config(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"[CONFIG] {message}")


def public_url_is_valid(url: str) -> bool:
    value = str(url or "").strip().lower()
    return value.startswith("https://") and "localhost" not in value and "127.0.0.1" not in value and len(value) > len("https://a.b")


def payer_domain_is_valid(domain: str) -> bool:
    value = str(domain or "").strip().lower()
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value))


DATABASE_URL = normalize_database_url(os.getenv("DATABASE_URL", ""))
if not DATABASE_URL:
    if IS_PRODUCTION:
        raise RuntimeError("[CONFIG] DATABASE_URL é obrigatório em produção. Configure PostgreSQL no Render.")
    DATABASE_URL = DEFAULT_DATABASE_URL

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin" if not IS_PRODUCTION else "").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
if not ADMIN_PASSWORD and not IS_PRODUCTION:
    ADMIN_PASSWORD = SAFE_DEV_ADMIN_PASSWORD

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
if not JWT_SECRET and not IS_PRODUCTION:
    JWT_SECRET = SAFE_DEV_JWT_SECRET

try:
    SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
except ValueError:
    raise RuntimeError("[CONFIG] SESSION_DAYS precisa ser um número inteiro.")
SESSION_DAYS = max(1, min(365, SESSION_DAYS))

PAYMENT_PROVIDER = os.getenv("PAYMENT_PROVIDER", "manual").strip().casefold() or "manual"
MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "").strip()
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "").strip()
MERCADOPAGO_PAYER_EMAIL_DOMAIN = os.getenv("MERCADOPAGO_PAYER_EMAIL_DOMAIN", "pcultramanager.com.br").strip().lower() or "pcultramanager.com.br"
try:
    MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS = int(os.getenv("MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS", "900"))
except ValueError:
    raise RuntimeError("[CONFIG] MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS precisa ser um número inteiro.")
MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS = max(60, min(86400, MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
if not PUBLIC_BASE_URL and not IS_PRODUCTION:
    PUBLIC_BASE_URL = "http://localhost:8000"

# E-mail transacional: usado para comprovante, tutorial e validade após pagamento aprovado.
# Não bloqueia o servidor se não estiver configurado. Em produção, configure SMTP_* no Render.
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").strip().lower() in {"1", "true", "yes", "sim"}
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
try:
    SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
except ValueError:
    raise RuntimeError("[CONFIG] SMTP_PORT precisa ser um número inteiro.")
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME).strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "PC Ultra Manager").strip() or "PC Ultra Manager"
SMTP_SUPPORT_EMAIL = os.getenv("SMTP_SUPPORT_EMAIL", SMTP_FROM_EMAIL).strip()
SMTP_USE_SSL_VALUE = os.getenv("SMTP_USE_SSL", "auto").strip().lower()
SMTP_USE_STARTTLS_VALUE = os.getenv("SMTP_USE_STARTTLS", "auto").strip().lower()
SMTP_USE_SSL = (SMTP_PORT == 465) if SMTP_USE_SSL_VALUE in {"", "auto"} else SMTP_USE_SSL_VALUE in {"1", "true", "yes", "sim"}
SMTP_USE_STARTTLS = (not SMTP_USE_SSL) if SMTP_USE_STARTTLS_VALUE in {"", "auto"} else SMTP_USE_STARTTLS_VALUE in {"1", "true", "yes", "sim"}

APP_LATEST_VERSION = os.getenv("APP_LATEST_VERSION", "4.1.1-security-env").strip()
APP_CHANNEL = os.getenv("APP_CHANNEL", "Acesso Antecipado Beta RC3").strip()
APP_DOWNLOAD_URL = os.getenv("APP_DOWNLOAD_URL", "").strip()
APP_CHANGELOG = os.getenv("APP_CHANGELOG", "Acesso Antecipado Beta com compra PIX antes do login, Beta Gate melhorado, dashboard, suporte e segurança.").strip()
CREATE_TEST_KEY = os.getenv("CREATE_TEST_KEY", "false").strip().lower() in {"1", "true", "yes", "sim"}
SYNC_ADMIN_PASSWORD = os.getenv("SYNC_ADMIN_PASSWORD", "true").strip().lower() in {"1", "true", "yes", "sim"}

require_config(PAYMENT_PROVIDER in {"manual", "mercadopago"}, "PAYMENT_PROVIDER precisa ser 'manual' ou 'mercadopago'.")
require_config(bool(ADMIN_USERNAME), "ADMIN_USERNAME é obrigatório.")
require_config(bool(ADMIN_PASSWORD), "ADMIN_PASSWORD é obrigatório.")
require_config(bool(JWT_SECRET), "JWT_SECRET é obrigatório.")
require_config(payer_domain_is_valid(MERCADOPAGO_PAYER_EMAIL_DOMAIN), "MERCADOPAGO_PAYER_EMAIL_DOMAIN precisa ser um domínio público válido, exemplo: pcultramanager.com.br.")
if EMAIL_ENABLED:
    require_config(bool(SMTP_HOST), "SMTP_HOST é obrigatório quando EMAIL_ENABLED=true.")
    require_config(SMTP_PORT > 0, "SMTP_PORT precisa ser válido quando EMAIL_ENABLED=true.")
    require_config(bool(SMTP_FROM_EMAIL) and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", SMTP_FROM_EMAIL), "SMTP_FROM_EMAIL precisa ser um e-mail válido quando EMAIL_ENABLED=true.")

if IS_PRODUCTION:
    require_config(not DATABASE_URL.startswith("sqlite"), "DATABASE_URL não pode ser SQLite em produção. Use PostgreSQL.")
    require_config(ADMIN_PASSWORD not in FORBIDDEN_PRODUCTION_SECRETS and len(ADMIN_PASSWORD) >= 12, "ADMIN_PASSWORD precisa ser forte e não pode usar senha padrão.")
    require_config(JWT_SECRET not in FORBIDDEN_PRODUCTION_SECRETS and len(JWT_SECRET) >= 32, "JWT_SECRET precisa ter pelo menos 32 caracteres e não pode ser padrão.")
    require_config(PUBLIC_BASE_URL and public_url_is_valid(PUBLIC_BASE_URL), "PUBLIC_BASE_URL precisa ser uma URL pública HTTPS em produção.")
    if PAYMENT_PROVIDER == "mercadopago":
        require_config(MERCADOPAGO_ACCESS_TOKEN.startswith("APP_USR-") or MERCADOPAGO_ACCESS_TOKEN.startswith("TEST-"), "MERCADOPAGO_ACCESS_TOKEN ausente ou inválido.")
        require_config(len(MERCADOPAGO_WEBHOOK_SECRET) >= 20, "MERCADOPAGO_WEBHOOK_SECRET é obrigatório em produção com Mercado Pago.")
        require_config(PUBLIC_BASE_URL.startswith("https://"), "PUBLIC_BASE_URL precisa usar HTTPS para webhooks do Mercado Pago.")
else:
    if PAYMENT_PROVIDER == "mercadopago":
        require_config(bool(MERCADOPAGO_ACCESS_TOKEN), "MERCADOPAGO_ACCESS_TOKEN é obrigatório quando PAYMENT_PROVIDER=mercadopago.")
        require_config(bool(PUBLIC_BASE_URL), "PUBLIC_BASE_URL é obrigatório quando PAYMENT_PROVIDER=mercadopago.")

app = FastAPI(title="PC Ultra Manager Server", version=APP_VERSION)
security = HTTPBearer(auto_error=False)

cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "*").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine_kwargs: Dict[str, Any] = {"future": True, "pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
metadata = MetaData()


# ==================================================
# TABELAS
# ==================================================

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(80), unique=True, nullable=False, index=True),
    Column("password_hash", Text, nullable=False),
    Column("recovery_key_hash", Text, nullable=False),
    Column("role", String(20), nullable=False, default="user"),
    Column("plan", String(30), nullable=False, default="free"),
    Column("premium_until", DateTime(timezone=True), nullable=True),
    Column("permanent", Boolean, nullable=False, default=False),
    Column("disabled", Boolean, nullable=False, default=False),
    Column("ban_level", String(40), nullable=True),
    Column("ban_message", Text, nullable=True),
    Column("banned_until", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("updated_at", DateTime(timezone=True), nullable=True),
)

sessions = Table(
    "sessions",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("token_hash", Text, unique=True, nullable=False, index=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

license_keys = Table(
    "license_keys",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("key_code_hash", Text, unique=True, nullable=False, index=True),
    Column("display_name", String(120), nullable=False),
    Column("plan", String(30), nullable=False),
    Column("duration_minutes", Integer, nullable=True),
    Column("permanent", Boolean, nullable=False, default=False),
    Column("is_used", Boolean, nullable=False, default=False),
    Column("revoked", Boolean, nullable=False, default=False),
    Column("used_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("used_at", DateTime(timezone=True), nullable=True),
    Column("created_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
)

admin_logs = Table(
    "admin_logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("admin_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("action", String(120), nullable=False),
    Column("target", Text, nullable=True),
    Column("details", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
)

app_logs = Table(
    "app_logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("action", String(120), nullable=False),
    Column("details", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
)

orders = Table(
    "orders",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("plan", String(30), nullable=False),
    Column("plan_title", String(80), nullable=False),
    Column("option_name", String(120), nullable=False),
    Column("duration_label", String(80), nullable=False),
    Column("duration_minutes", Integer, nullable=True),
    Column("permanent", Boolean, nullable=False, default=False),
    Column("price_cents", Integer, nullable=False),
    Column("access_type", String(30), nullable=False, default="one_time"),
    Column("duration_days", Integer, nullable=True),
    Column("access_expires_at", DateTime(timezone=True), nullable=True),
    Column("status", String(30), nullable=False, default="pending"),
    Column("user_message", Text, nullable=True),
    Column("admin_message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("approved_at", DateTime(timezone=True), nullable=True),
    Column("approved_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    Column("cancelled_at", DateTime(timezone=True), nullable=True),
    Column("payment_provider", String(40), nullable=True),
    Column("payment_id", String(120), nullable=True),
    Column("payment_status", String(60), nullable=True),
    Column("payment_qr_code", Text, nullable=True),
    Column("payment_qr_code_base64", Text, nullable=True),
    Column("payment_ticket_url", Text, nullable=True),
    Column("payment_created_at", DateTime(timezone=True), nullable=True),
    Column("payment_paid_at", DateTime(timezone=True), nullable=True),
)


beta_keys = Table(
    "beta_keys",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("key_hash", Text, unique=True, nullable=False, index=True),
    Column("display_name", String(120), nullable=False),
    Column("access_level", String(40), nullable=False, default="closed_beta"),
    Column("max_uses", Integer, nullable=False, default=1),
    Column("current_uses", Integer, nullable=False, default=0),
    Column("revoked", Boolean, nullable=False, default=False),
    Column("message", Text, nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("created_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("last_used_at", DateTime(timezone=True), nullable=True),
)


beta_access_orders = Table(
    "beta_access_orders",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("order_token", Text, unique=True, nullable=False, index=True),
    Column("buyer_name", String(120), nullable=True),
    Column("buyer_email", String(180), nullable=True),
    Column("device_id", Text, nullable=True),
    Column("option_name", String(120), nullable=False),
    Column("duration_label", String(80), nullable=False),
    Column("expires_days", Integer, nullable=True),
    Column("permanent", Boolean, nullable=False, default=False),
    Column("price_cents", Integer, nullable=False),
    Column("status", String(30), nullable=False, default="payment_pending"),
    Column("payment_provider", String(40), nullable=True),
    Column("payment_id", String(120), nullable=True),
    Column("payment_status", String(60), nullable=True),
    Column("payment_qr_code", Text, nullable=True),
    Column("payment_qr_code_base64", Text, nullable=True),
    Column("payment_ticket_url", Text, nullable=True),
    Column("payment_created_at", DateTime(timezone=True), nullable=True),
    Column("payment_paid_at", DateTime(timezone=True), nullable=True),
    Column("beta_key_code", Text, nullable=True),
    Column("beta_key_id", Integer, ForeignKey("beta_keys.id"), nullable=True),
    Column("message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
)


support_tickets = Table(
    "support_tickets",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("category", String(60), nullable=False, default="bug"),
    Column("priority", String(30), nullable=False, default="media"),
    Column("title", String(180), nullable=False),
    Column("message", Text, nullable=False),
    Column("status", String(30), nullable=False, default="aberto"),
    Column("admin_message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("updated_at", DateTime(timezone=True), nullable=True),
)

security_events = Table(
    "security_events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("username", String(80), nullable=True),
    Column("action", String(80), nullable=False),
    Column("success", Boolean, nullable=False, default=False),
    Column("details", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
)

# Loja de temas: permite um site separado vender temas usando o mesmo login do app.
themes = Table(
    "themes",
    metadata,
    Column("id", String(80), primary_key=True),
    Column("name", String(120), nullable=False),
    Column("description", Text, nullable=True),
    Column("price_cents", Integer, nullable=False, default=0),
    Column("preview_url", Text, nullable=True),
    Column("accent_color", String(40), nullable=True),
    Column("category", String(80), nullable=False, default="premium"),
    Column("access_type", String(30), nullable=False, default="one_time"),
    Column("duration_days", Integer, nullable=True),
    Column("duration_label", String(80), nullable=True),
    Column("event_starts_at", DateTime(timezone=True), nullable=True),
    Column("event_ends_at", DateTime(timezone=True), nullable=True),
    Column("event_label", String(120), nullable=True),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("updated_at", DateTime(timezone=True), nullable=True),
)

theme_orders = Table(
    "theme_orders",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("theme_id", String(80), ForeignKey("themes.id"), nullable=False),
    Column("theme_name", String(120), nullable=False),
    Column("price_cents", Integer, nullable=False),
    Column("access_type", String(30), nullable=False, default="one_time"),
    Column("duration_days", Integer, nullable=True),
    Column("access_expires_at", DateTime(timezone=True), nullable=True),
    Column("status", String(30), nullable=False, default="pending"),
    Column("buyer_name", String(120), nullable=True),
    Column("buyer_email", String(180), nullable=True),
    Column("receipt_email_sent_at", DateTime(timezone=True), nullable=True),
    Column("receipt_email_error", Text, nullable=True),
    Column("admin_message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    Column("cancelled_at", DateTime(timezone=True), nullable=True),
    Column("payment_provider", String(40), nullable=True),
    Column("payment_id", String(120), nullable=True),
    Column("payment_status", String(60), nullable=True),
    Column("payment_qr_code", Text, nullable=True),
    Column("payment_qr_code_base64", Text, nullable=True),
    Column("payment_ticket_url", Text, nullable=True),
    Column("payment_created_at", DateTime(timezone=True), nullable=True),
    Column("payment_paid_at", DateTime(timezone=True), nullable=True),
)

user_themes = Table(
    "user_themes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False, index=True),
    Column("theme_id", String(80), ForeignKey("themes.id"), nullable=False, index=True),
    Column("source", String(60), nullable=False, default="purchase"),
    Column("order_id", Integer, ForeignKey("theme_orders.id"), nullable=True),
    Column("granted_by", Integer, ForeignKey("users.id"), nullable=True),
    Column("note", Text, nullable=True),
    Column("purchased_at", DateTime(timezone=True), nullable=False, default=lambda: now_utc()),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("status", String(30), nullable=False, default="active"),
)


DEFAULT_THEME_CATALOG = [
    {
        "id": "windows_11_pro_glass",
        "name": "Windows 11 Pro Glass",
        "description": "Tema premium com vidro translúcido, sombras suaves e visual inspirado em Windows 11 Pro.",
        "price_cents": 990,
        "preview_url": "",
        "accent_color": "#0078D4",
        "category": "premium",
        "access_type": "one_time",
        "duration_days": None,
        "duration_label": "Vitalício",
        "is_active": True,
    },
    {
        "id": "cinema_dark_luxury",
        "name": "Cinema Dark Luxury",
        "description": "Tema escuro cinematográfico com profundidade, aura premium e acabamento elegante.",
        "price_cents": 1290,
        "preview_url": "",
        "accent_color": "#B99A5B",
        "category": "cinema",
        "access_type": "one_time",
        "duration_days": None,
        "duration_label": "Vitalício",
        "is_active": True,
    },
    {
        "id": "liquid_glass_pro",
        "name": "Liquid Glass Pro",
        "description": "Tema com efeito liquid glass, transparência controlada e aparência moderna.",
        "price_cents": 1490,
        "preview_url": "",
        "accent_color": "#7DD3FC",
        "category": "glass",
        "access_type": "one_time",
        "duration_days": None,
        "duration_label": "Vitalício",
        "is_active": True,
    },
    {
        "id": "diamond_black_event",
        "name": "Diamond Black",
        "description": "Tema especial de evento semanal com fundo preto cristal, brilho de diamante, letras em branco gelo e contornos premium de alto contraste. Fica disponível na loja por tempo limitado; quem compra recebe acesso permanente na conta.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#F8FAFC",
        "category": "evento semanal",
        "access_type": "one_time",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Disponível por 7 dias na loja • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "arctic_neon_weekly",
        "name": "Arctic Neon",
        "description": "Tema de evento semanal com neon azul gelo, fundo escuro glacial, linhas cristalinas e brilho técnico futurista. Aparece somente na aba Evento Semanal; quem compra recebe acesso permanente.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#7DD3FC",
        "category": "evento semanal",
        "access_type": "event_sale",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Tema de evento semanal • disponível por 7 dias • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "crimson_cyber_weekly",
        "name": "Crimson Cyber",
        "description": "Tema de evento semanal com vermelho cyber, preto profundo, contornos agressivos e atmosfera gamer premium. Aparece somente na aba Evento Semanal; quem compra recebe acesso permanente.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#FF315A",
        "category": "evento semanal",
        "access_type": "event_sale",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Tema de evento semanal • disponível por 7 dias • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "royal_gold_weekly",
        "name": "Royal Gold",
        "description": "Tema de evento semanal com dourado nobre, fundo preto luxo, bordas premium e sensação de painel executivo. Aparece somente na aba Evento Semanal; quem compra recebe acesso permanente.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#F6C65B",
        "category": "evento semanal",
        "access_type": "event_sale",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Tema de evento semanal • disponível por 7 dias • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "purple_galaxy_weekly",
        "name": "Purple Galaxy",
        "description": "Tema de evento semanal com roxo cósmico, brilho de galáxia, fundo espacial e cards com profundidade cinematográfica. Aparece somente na aba Evento Semanal; quem compra recebe acesso permanente.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#A855F7",
        "category": "evento semanal",
        "access_type": "event_sale",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Tema de evento semanal • disponível por 7 dias • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "emerald_obsidian_weekly",
        "name": "Emerald Obsidian",
        "description": "Tema de evento semanal com verde esmeralda, preto obsidiana, reflexos minerais e aura técnica elegante. Aparece somente na aba Evento Semanal; quem compra recebe acesso permanente.",
        "price_cents": 250,
        "preview_url": "",
        "accent_color": "#34D399",
        "category": "evento semanal",
        "access_type": "event_sale",
        "duration_days": None,
        "duration_label": "Compra permanente",
        "event_label": "Tema de evento semanal • disponível por 7 dias • acesso permanente após compra",
        "is_active": True,
    },
    {
        "id": "matrix_effect_subscription",
        "name": "Matrix Effect",
        "description": "Tema estilo Matrix com chuva de códigos, brilho verde digital, atmosfera hacker/cyber e efeito visual de terminal futurista. Assinatura mensal: custa R$ 0,50 e precisa renovar a cada 30 dias.",
        "price_cents": 50,
        "preview_url": "",
        "accent_color": "#00FF66",
        "category": "assinatura",
        "access_type": "subscription",
        "duration_days": 30,
        "duration_label": "30 dias",
        "is_active": True,
    },
]


WEEKLY_EVENT_THEME_IDS = [
    "arctic_neon_weekly",
    "crimson_cyber_weekly",
    "royal_gold_weekly",
    "purple_galaxy_weekly",
    "emerald_obsidian_weekly",
]
WEEKLY_EVENT_ANCHOR = datetime(2026, 1, 5, tzinfo=timezone.utc)  # Segunda-feira fixa para rotação estável.
WEEKLY_EVENT_PRICE_CENTS = 250



# ==================================================
# HELPERS
# ==================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_username(username: str) -> str:
    return str(username or "").strip()


def normalize_plan(plan: str) -> str:
    value = str(plan or "free").strip().casefold()
    aliases = {
        "patrocinador": "patrocinador",
        "sponsor": "patrocinador",
        "premium": "premium",
        "admin": "admin",
        "free": "free",
    }
    if value not in aliases:
        raise HTTPException(status_code=400, detail="Plano inválido")
    return aliases[value]


def public_plan_name(plan: str) -> str:
    return {
        "free": "Free",
        "premium": "Premium",
        "patrocinador": "Patrocinador",
        "admin": "Admin",
    }.get(plan, str(plan).title())


PLAN_CATALOG = {
    "free": [
        {"option_name": "Free", "duration_label": "Sem limite", "duration_minutes": None, "permanent": True, "price_cents": 0},
    ],
    "premium": [
        {"option_name": "Teste técnico", "duration_label": "1 minuto", "duration_minutes": 1, "permanent": False, "price_cents": 5},
        {"option_name": "Teste rápido", "duration_label": "30 minutos", "duration_minutes": 30, "permanent": False, "price_cents": 10},
        {"option_name": "Diário", "duration_label": "1 dia", "duration_minutes": 1440, "permanent": False, "price_cents": 50},
        {"option_name": "Semanal", "duration_label": "7 dias", "duration_minutes": 10080, "permanent": False, "price_cents": 150},
        {"option_name": "Quinzena gamer", "duration_label": "15 dias", "duration_minutes": 21600, "permanent": False, "price_cents": 250},
        {"option_name": "Mensal Premium", "duration_label": "30 dias", "duration_minutes": 43200, "permanent": False, "price_cents": 499},
        {"option_name": "Trimestral Pro", "duration_label": "3 meses", "duration_minutes": 129600, "permanent": False, "price_cents": 1000},
        {"option_name": "Semestral Ultra", "duration_label": "6 meses", "duration_minutes": 259200, "permanent": False, "price_cents": 1800},
        {"option_name": "Anual Master", "duration_label": "1 ano", "duration_minutes": 525600, "permanent": False, "price_cents": 3000},
        {"option_name": "Permanente", "duration_label": "Vitalício", "duration_minutes": None, "permanent": True, "price_cents": 5000},
    ],
    "patrocinador": [
        {"option_name": "Teste sponsor", "duration_label": "1 minuto", "duration_minutes": 1, "permanent": False, "price_cents": 10},
        {"option_name": "Teste rápido", "duration_label": "30 minutos", "duration_minutes": 30, "permanent": False, "price_cents": 25},
        {"option_name": "Diário", "duration_label": "1 dia", "duration_minutes": 1440, "permanent": False, "price_cents": 100},
        {"option_name": "Semanal", "duration_label": "7 dias", "duration_minutes": 10080, "permanent": False, "price_cents": 300},
        {"option_name": "Quinzena", "duration_label": "15 dias", "duration_minutes": 21600, "permanent": False, "price_cents": 500},
        {"option_name": "Mensal Sponsor", "duration_label": "30 dias", "duration_minutes": 43200, "permanent": False, "price_cents": 999},
        {"option_name": "Trimestral Elite", "duration_label": "3 meses", "duration_minutes": 129600, "permanent": False, "price_cents": 2000},
        {"option_name": "Semestral Elite", "duration_label": "6 meses", "duration_minutes": 259200, "permanent": False, "price_cents": 3500},
        {"option_name": "Anual Elite", "duration_label": "1 ano", "duration_minutes": 525600, "permanent": False, "price_cents": 6000},
        {"option_name": "Permanente Elite", "duration_label": "Vitalício", "duration_minutes": None, "permanent": True, "price_cents": 10000},
    ],
}


BETA_ACCESS_CATALOG = [
    {"option_name": "Beta Diário", "duration_label": "1 dia", "expires_days": 1, "permanent": False, "price_cents": 50},
    {"option_name": "Beta Semanal", "duration_label": "7 dias", "expires_days": 7, "permanent": False, "price_cents": 150},
    {"option_name": "Beta 15 dias", "duration_label": "15 dias", "expires_days": 15, "permanent": False, "price_cents": 250},
    {"option_name": "Beta 30 dias", "duration_label": "30 dias", "expires_days": 30, "permanent": False, "price_cents": 499},
    {"option_name": "Beta Permanente", "duration_label": "Permanente da Beta", "expires_days": None, "permanent": True, "price_cents": 1000},
]


def beta_access_catalog_public() -> Dict[str, Any]:
    return {
        "title": "Acesso Antecipado Beta",
        "channel": APP_CHANNEL,
        "description": "Acesso fechado antes do login. Compre uma key beta via PIX ou use uma key enviada pelo admin.",
        "options": [{**option, "price_label": price_label(option["price_cents"])} for option in BETA_ACCESS_CATALOG],
    }


def find_beta_access_option(option_name: str, expires_days: Optional[int], permanent: bool, price_cents: int) -> Dict[str, Any]:
    normalized_name = str(option_name or "").strip().casefold()
    for option in BETA_ACCESS_CATALOG:
        same_name = option["option_name"].casefold() == normalized_name
        same_price = int(option["price_cents"]) == int(price_cents)
        same_permanent = bool(option["permanent"]) == bool(permanent)
        option_days = option.get("expires_days")
        same_duration = (option_days is None and expires_days in (None, 0, -1)) or (option_days == expires_days)
        if same_name and same_price and same_permanent and same_duration:
            return option
    raise HTTPException(status_code=400, detail="Opção de acesso beta inválida ou valor diferente do catálogo")


def price_label(price_cents: int) -> str:
    return f"R$ {price_cents / 100:.2f}".replace(".", ",")


def public_catalog() -> Dict[str, Any]:
    return {
        "plans": [
            {
                "plan": plan,
                "plan_title": public_plan_name(plan),
                "options": [
                    {**option, "price_label": price_label(option["price_cents"])}
                    for option in options
                ],
            }
            for plan, options in PLAN_CATALOG.items()
            if plan != "admin"
        ]
    }


def find_catalog_option(plan: str, option_name: str, duration_minutes: Optional[int], permanent: bool, price_cents: int) -> Dict[str, Any]:
    plan = normalize_plan(plan)
    if plan == "admin":
        raise HTTPException(status_code=400, detail="Pedido de plano admin não é permitido")
    options = PLAN_CATALOG.get(plan, [])
    normalized_name = str(option_name or "").strip().casefold()
    for option in options:
        same_name = option["option_name"].casefold() == normalized_name
        same_price = int(option["price_cents"]) == int(price_cents)
        same_permanent = bool(option["permanent"]) == bool(permanent)
        option_minutes = option.get("duration_minutes")
        same_duration = (option_minutes is None and duration_minutes in (None, 0, -1)) or (option_minutes == duration_minutes)
        if same_name and same_price and same_permanent and same_duration:
            return option
    raise HTTPException(status_code=400, detail="Plano/opção inválida ou valor diferente do catálogo")


def hash_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def password_hash(password: str) -> str:
    # PBKDF2 com salt. Também aceitamos SHA256 antigo em login para compatibilidade.
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256$120000${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            _, rounds, salt, digest = stored_hash.split("$", 3)
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                int(rounds),
            ).hex()
            return hmac.compare_digest(candidate, digest)
        except Exception:
            return False
    return hmac.compare_digest(hash_text(password), stored_hash)


def token_hash(token: str) -> str:
    return hashlib.sha256(f"{JWT_SECRET}:{token}".encode("utf-8")).hexdigest()


def serialize_dt(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def row_dict(row: Any) -> Dict[str, Any]:
    return dict(row._mapping if hasattr(row, "_mapping") else row)


def get_optional_user_by_token(authorization: Optional[str] = Header(default=None)) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    try:
        raw = str(authorization or "").strip()
        if raw.lower().startswith("bearer "):
            raw = raw.split(" ", 1)[1].strip()
        if not raw:
            return None
        hashed = token_hash(raw)
        with engine.begin() as conn:
            result = conn.execute(
                select(users, sessions.c.expires_at.label("session_expires_at"))
                .select_from(sessions.join(users, users.c.id == sessions.c.user_id))
                .where(sessions.c.token_hash == hashed)
            ).first()
            if result is None:
                return None
            data = row_dict(result)
            expires_at = data.get("session_expires_at")
            if expires_at and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at and expires_at <= now_utc():
                conn.execute(sessions.delete().where(sessions.c.token_hash == hashed))
                return None
            return data
    except Exception:
        return None


def is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "admin" or user.get("plan") == "admin"


def safe_details(details: Any) -> str:
    if details is None:
        return ""
    return str(details)[:5000]


def add_admin_log(conn, admin_id: Optional[int], action: str, target: str = "", details: Any = None) -> None:
    conn.execute(
        admin_logs.insert().values(
            admin_id=admin_id,
            action=action,
            target=str(target or "")[:500],
            details=safe_details(details),
            created_at=now_utc(),
        )
    )


def add_app_log(conn, user_id: Optional[int], action: str, details: Any = None) -> None:
    conn.execute(
        app_logs.insert().values(
            user_id=user_id,
            action=str(action or "")[:120],
            details=safe_details(details),
            created_at=now_utc(),
        )
    )


def add_security_event(conn, action: str, success: bool, user_id: Optional[int] = None, username: Optional[str] = None, details: Any = None) -> None:
    conn.execute(
        security_events.insert().values(
            user_id=user_id,
            username=str(username or "")[:80] if username else None,
            action=str(action or "")[:80],
            success=bool(success),
            details=safe_details(details),
            created_at=now_utc(),
        )
    )


def recent_security_count(conn, action: str, user_id: Optional[int] = None, username: Optional[str] = None, minutes: int = 15) -> int:
    cutoff = now_utc() - timedelta(minutes=int(minutes))
    query = select(func.count()).select_from(security_events).where(
        security_events.c.action == action,
        security_events.c.success == False,  # noqa: E712
        security_events.c.created_at >= cutoff,
    )
    if user_id is not None:
        query = query.where(security_events.c.user_id == int(user_id))
    if username:
        query = query.where(security_events.c.username == str(username)[:80])
    return int(conn.execute(query).scalar_one() or 0)


def serialize_ticket(row: Any, username: Optional[str] = None) -> Dict[str, Any]:
    data = row_dict(row)
    return {
        "id": data.get("id"),
        "user_id": data.get("user_id"),
        "username": username or data.get("username"),
        "category": data.get("category"),
        "priority": data.get("priority"),
        "title": data.get("title"),
        "message": data.get("message"),
        "status": data.get("status"),
        "admin_message": data.get("admin_message"),
        "created_at": serialize_dt(data.get("created_at")),
        "updated_at": serialize_dt(data.get("updated_at")),
    }


def serialize_beta_key(row: Any) -> Dict[str, Any]:
    data = row_dict(row)
    max_uses = int(data.get("max_uses") or 0)
    current_uses = int(data.get("current_uses") or 0)
    expires_at = data.get("expires_at")
    expired = False
    if expires_at:
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        expired = expires_at <= now_utc()
    return {
        "id": data.get("id"),
        "display_name": data.get("display_name"),
        "access_level": data.get("access_level"),
        "max_uses": max_uses,
        "current_uses": current_uses,
        "remaining_uses": max(0, max_uses - current_uses) if max_uses > 0 else None,
        "revoked": bool(data.get("revoked")),
        "expired": expired,
        "available": (not bool(data.get("revoked"))) and (not expired) and (max_uses <= 0 or current_uses < max_uses),
        "message": data.get("message"),
        "expires_at": serialize_dt(data.get("expires_at")),
        "created_at": serialize_dt(data.get("created_at")),
        "last_used_at": serialize_dt(data.get("last_used_at")),
    }


def serialize_beta_access_order(row: Any) -> Dict[str, Any]:
    data = row_dict(row)
    return {
        "id": data.get("id"),
        "buyer_name": data.get("buyer_name"),
        "buyer_email": data.get("buyer_email"),
        "option_name": data.get("option_name"),
        "duration_label": data.get("duration_label"),
        "expires_days": data.get("expires_days"),
        "permanent": bool(data.get("permanent")),
        "price_cents": int(data.get("price_cents") or 0),
        "price_label": price_label(int(data.get("price_cents") or 0)),
        "status": data.get("status"),
        "payment_provider": data.get("payment_provider"),
        "payment_id": data.get("payment_id"),
        "payment_status": data.get("payment_status"),
        "payment_qr_code": data.get("payment_qr_code"),
        "payment_qr_code_base64": data.get("payment_qr_code_base64"),
        "payment_ticket_url": data.get("payment_ticket_url"),
        "beta_key_code": data.get("beta_key_code") if data.get("status") == "delivered" else None,
        "message": data.get("message"),
        "created_at": serialize_dt(data.get("created_at")),
        "payment_created_at": serialize_dt(data.get("payment_created_at")),
        "payment_paid_at": serialize_dt(data.get("payment_paid_at")),
        "delivered_at": serialize_dt(data.get("delivered_at")),
    }


def user_license_payload(user: Dict[str, Any]) -> Dict[str, Any]:
    plan = normalize_plan(user.get("plan", "free"))
    premium_until = user.get("premium_until")
    permanent = bool(user.get("permanent")) or plan == "admin"
    active = False
    expired = False
    remaining_seconds = 0

    if plan in {"premium", "patrocinador", "admin"}:
        if permanent:
            active = True
        elif premium_until:
            expires = premium_until
            if isinstance(expires, str):
                expires = datetime.fromisoformat(expires)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            delta = expires - now_utc()
            if delta.total_seconds() > 0:
                active = True
                remaining_seconds = int(delta.total_seconds())
            else:
                expired = True
                plan = "free"
        else:
            expired = True
            plan = "free"

    if plan == "free":
        active = False
        permanent = False
        remaining_seconds = 0

    return {
        "plan": plan,
        "plan_name": public_plan_name(plan),
        "premium_active": active,
        "active": active,
        "expired": expired,
        "premium_until": serialize_dt(premium_until) if active and not permanent else None,
        "expires_at": serialize_dt(premium_until) if active and not permanent else None,
        "remaining_seconds": remaining_seconds,
        "permanent": permanent,
    }


# ==================================================
# MODELOS
# ==================================================


class VerifyBetaRequest(BaseModel):
    key: str = Field(min_length=3, max_length=200)
    device_id: Optional[str] = None
    app_version: Optional[str] = None


class CreateBetaKeyRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)
    key_code: str = Field(min_length=3, max_length=200)
    access_level: str = "closed_beta"
    max_uses: int = 1
    expires_days: Optional[int] = None
    message: Optional[str] = None


class BetaKeyActionRequest(BaseModel):
    key_id: Optional[int] = None
    key_code: Optional[str] = None


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=6, max_length=200)


class LoginRequest(BaseModel):
    username: str
    password: str


class ActivateKeyRequest(BaseModel):
    key: str


class RecoverRequest(BaseModel):
    username: str
    recovery_key: str
    new_password: str = Field(min_length=6, max_length=200)


class RevokeKeyRequest(BaseModel):
    key_id: Optional[int] = None
    key_code: Optional[str] = None


class ChangePlanRequest(BaseModel):
    user_id: int
    plan: str
    premium_until: Optional[str] = None
    duration_minutes: Optional[int] = None
    permanent: Optional[bool] = None


class BanUserRequest(BaseModel):
    user_id: int
    level: str = "leve"
    message: str = "Conta suspensa pelo administrador."
    duration_minutes: Optional[int] = None


class UserIdRequest(BaseModel):
    user_id: int


class DeleteKeyRequest(BaseModel):
    key_id: Optional[int] = None
    key_code: Optional[str] = None


class RevokePlanRequest(BaseModel):
    user_id: int
    message: str = "Plano revogado pelo administrador."



class CreateBetaAccessOrderRequest(BaseModel):
    option_name: str
    duration_label: Optional[str] = None
    expires_days: Optional[int] = None
    permanent: bool = False
    price_cents: int
    buyer_name: Optional[str] = None
    buyer_email: Optional[str] = None
    device_id: Optional[str] = None


class CreateOrderRequest(BaseModel):
    plan: str
    option_name: str
    duration_label: str
    duration_minutes: Optional[int] = None
    permanent: bool = False
    price_cents: int
    user_message: Optional[str] = None


class OrderActionRequest(BaseModel):
    order_id: int
    message: Optional[str] = None


class LogRequest(BaseModel):
    action: str
    details: Optional[Any] = None


class SupportCreateRequest(BaseModel):
    category: str = "bug"
    priority: str = "media"
    title: str = Field(min_length=3, max_length=180)
    message: str = Field(min_length=5, max_length=5000)


class SupportUpdateRequest(BaseModel):
    ticket_id: int
    status: str = "em_analise"
    admin_message: Optional[str] = None


class ThemePurchaseRequest(BaseModel):
    theme_id: str = Field(min_length=2, max_length=80)
    buyer_name: Optional[str] = Field(default=None, max_length=120)
    buyer_email: Optional[str] = Field(default=None, max_length=180)


class ThemeCreateRequest(BaseModel):
    id: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = None
    price_cents: int = Field(ge=0)
    preview_url: Optional[str] = None
    accent_color: Optional[str] = Field(default=None, max_length=40)
    category: str = Field(default="premium", max_length=80)
    access_type: str = Field(default="one_time", max_length=30)
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)
    duration_label: Optional[str] = Field(default=None, max_length=80)
    is_active: bool = True


class ThemeGiveRequest(BaseModel):
    user_id: int
    theme_id: str = Field(min_length=2, max_length=80)
    message: Optional[str] = None


class ThemeRemoveRequest(BaseModel):
    user_id: int
    theme_id: str = Field(min_length=2, max_length=80)


class ThemeOrderActionRequest(BaseModel):
    order_id: int
    message: Optional[str] = None


# ==================================================
# BANCO / BOOTSTRAP
# ==================================================

def ensure_schema_updates() -> None:
    """Adiciona colunas novas em bancos já existentes sem apagar dados."""
    if DATABASE_URL.startswith("postgresql"):
        statements = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_level VARCHAR(40)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_message TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_provider VARCHAR(40)",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id VARCHAR(120)",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status VARCHAR(60)",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_qr_code TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_qr_code_base64 TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_ticket_url TEXT",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_created_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_paid_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS access_type VARCHAR(30) DEFAULT 'one_time'",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS duration_days INTEGER",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS duration_label VARCHAR(80)",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS event_starts_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS event_ends_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE themes ADD COLUMN IF NOT EXISTS event_label VARCHAR(120)",
            "ALTER TABLE theme_orders ADD COLUMN IF NOT EXISTS access_type VARCHAR(30) DEFAULT 'one_time'",
            "ALTER TABLE theme_orders ADD COLUMN IF NOT EXISTS duration_days INTEGER",
            "ALTER TABLE theme_orders ADD COLUMN IF NOT EXISTS access_expires_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE theme_orders ADD COLUMN IF NOT EXISTS receipt_email_sent_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE theme_orders ADD COLUMN IF NOT EXISTS receipt_email_error TEXT",
            "ALTER TABLE user_themes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE",
            "ALTER TABLE user_themes ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'active'",
            "UPDATE themes SET access_type = 'one_time' WHERE access_type IS NULL",
            "UPDATE themes SET duration_label = 'Vitalício' WHERE duration_label IS NULL AND COALESCE(access_type, 'one_time') <> 'subscription'",
            "UPDATE themes SET access_type = 'subscription', duration_days = 30, duration_label = '30 dias', category = 'assinatura', price_cents = 50 WHERE id = 'matrix_effect_subscription'",
            "UPDATE themes SET access_type = 'event_sale', duration_days = NULL, duration_label = 'Compra permanente', category = 'evento semanal', price_cents = 250, event_label = 'Evento semanal: disponível apenas na aba exclusiva; acesso permanente após compra' WHERE id IN ('diamond_black_event','arctic_neon_weekly','crimson_cyber_weekly','royal_gold_weekly','purple_galaxy_weekly','emerald_obsidian_weekly')",
            "UPDATE user_themes SET status = 'active' WHERE status IS NULL",
            "UPDATE user_themes SET expires_at = purchased_at + INTERVAL '30 days' WHERE theme_id = 'matrix_effect_subscription' AND expires_at IS NULL",
            "UPDATE user_themes SET expires_at = NULL WHERE theme_id = 'diamond_black_event'",
            "UPDATE theme_orders SET access_type = 'one_time', duration_days = NULL, access_expires_at = NULL WHERE theme_id = 'diamond_black_event' AND status = 'delivered'",
        ]
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
        return

    if DATABASE_URL.startswith("sqlite"):
        with engine.begin() as conn:
            existing = {row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()}
            if "ban_level" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN ban_level VARCHAR(40)"))
            if "ban_message" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN ban_message TEXT"))
            if "banned_until" not in existing:
                conn.execute(text("ALTER TABLE users ADD COLUMN banned_until DATETIME"))
            order_existing = {row[1] for row in conn.execute(text("PRAGMA table_info(orders)")).fetchall()}
            order_columns = {
                "payment_provider": "VARCHAR(40)",
                "payment_id": "VARCHAR(120)",
                "payment_status": "VARCHAR(60)",
                "payment_qr_code": "TEXT",
                "payment_qr_code_base64": "TEXT",
                "payment_ticket_url": "TEXT",
                "payment_created_at": "DATETIME",
                "payment_paid_at": "DATETIME",
            }
            for col, ddl in order_columns.items():
                if col not in order_existing:
                    conn.execute(text(f"ALTER TABLE orders ADD COLUMN {col} {ddl}"))

            def add_missing(table_name: str, columns: Dict[str, str]) -> None:
                existing_cols = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()}
                for col, ddl in columns.items():
                    if col not in existing_cols:
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col} {ddl}"))

            add_missing("themes", {
                "access_type": "VARCHAR(30) DEFAULT 'one_time'",
                "duration_days": "INTEGER",
                "duration_label": "VARCHAR(80)",
                "event_starts_at": "DATETIME",
                "event_ends_at": "DATETIME",
                "event_label": "VARCHAR(120)",
            })
            add_missing("theme_orders", {
                "access_type": "VARCHAR(30) DEFAULT 'one_time'",
                "duration_days": "INTEGER",
                "access_expires_at": "DATETIME",
                "receipt_email_sent_at": "DATETIME",
                "receipt_email_error": "TEXT",
            })
            add_missing("user_themes", {
                "expires_at": "DATETIME",
                "status": "VARCHAR(30) DEFAULT 'active'",
            })
            conn.execute(text("UPDATE themes SET access_type = 'one_time' WHERE access_type IS NULL"))
            conn.execute(text("UPDATE themes SET duration_label = 'Vitalício' WHERE duration_label IS NULL AND COALESCE(access_type, 'one_time') <> 'subscription'"))
            conn.execute(text("UPDATE themes SET access_type = 'subscription', duration_days = 30, duration_label = '30 dias', category = 'assinatura', price_cents = 50 WHERE id = 'matrix_effect_subscription'"))
            conn.execute(text("UPDATE themes SET access_type = 'event_sale', duration_days = NULL, duration_label = 'Compra permanente', category = 'evento semanal', price_cents = 250, event_label = 'Evento semanal: disponível apenas na aba exclusiva; acesso permanente após compra' WHERE id IN ('diamond_black_event','arctic_neon_weekly','crimson_cyber_weekly','royal_gold_weekly','purple_galaxy_weekly','emerald_obsidian_weekly')"))
            conn.execute(text("UPDATE user_themes SET status = 'active' WHERE status IS NULL"))
            conn.execute(text("UPDATE user_themes SET expires_at = datetime(purchased_at, '+30 days') WHERE theme_id = 'matrix_effect_subscription' AND expires_at IS NULL"))
            conn.execute(text("UPDATE user_themes SET expires_at = NULL WHERE theme_id = 'diamond_black_event'"))
            conn.execute(text("UPDATE theme_orders SET access_type = 'one_time', duration_days = NULL, access_expires_at = NULL WHERE theme_id = 'diamond_black_event' AND status = 'delivered'"))


def init_db() -> None:
    metadata.create_all(engine)
    ensure_schema_updates()
    with engine.begin() as conn:
        # Admin padrão controlado por Environment do Render.
        # IMPORTANTE: em produção, sempre sincroniza a senha do admin com ADMIN_PASSWORD.
        # Isso evita o problema de trocar a senha no Render e o banco continuar preso
        # com a senha antiga.
        admin = conn.execute(select(users).where(users.c.username == ADMIN_USERNAME)).first()
        recovery_key = "REC-" + secrets.token_hex(8).upper()
        if admin is None:
            conn.execute(
                users.insert().values(
                    username=ADMIN_USERNAME,
                    password_hash=password_hash(ADMIN_PASSWORD),
                    recovery_key_hash=hash_text(recovery_key),
                    role="admin",
                    plan="admin",
                    permanent=True,
                    disabled=False,
                    created_at=now_utc(),
                    updated_at=now_utc(),
                )
            )
            print(f"[BOOT] Admin criado/sincronizado: {ADMIN_USERNAME}", flush=True)
        else:
            admin_row = row_dict(admin)
            values = {
                "role": "admin",
                "plan": "admin",
                "permanent": True,
                "disabled": False,
                "updated_at": now_utc(),
            }
            if SYNC_ADMIN_PASSWORD:
                values["password_hash"] = password_hash(ADMIN_PASSWORD)
            conn.execute(update(users).where(users.c.id == admin_row["id"]).values(**values))
            sync_label = "com senha sincronizada" if SYNC_ADMIN_PASSWORD else "sem alterar senha"
            print(f"[BOOT] Admin atualizado/sincronizado: {ADMIN_USERNAME} ({sync_label})", flush=True)

        # Key de teste só nasce quando CREATE_TEST_KEY=true.
        # Em produção, isso evita chave premium padrão criada sem querer.
        if CREATE_TEST_KEY and not IS_PRODUCTION:
            test_hash = hash_text("Key Teste")
            existing = conn.execute(select(license_keys.c.id).where(license_keys.c.key_code_hash == test_hash)).first()
            if existing is None:
                conn.execute(
                    license_keys.insert().values(
                        key_code_hash=test_hash,
                        display_name="Key Teste",
                        plan="premium",
                        duration_minutes=30,
                        permanent=False,
                        created_at=now_utc(),
                    )
                )

        # Catálogo inicial da loja de temas. Não sobrescreve temas já existentes.
        for theme in DEFAULT_THEME_CATALOG:
            existing_theme = conn.execute(select(themes.c.id).where(themes.c.id == theme["id"])).first()
            if existing_theme is None:
                conn.execute(
                    themes.insert().values(
                        id=theme["id"],
                        name=theme["name"],
                        description=theme.get("description"),
                        price_cents=int(theme.get("price_cents") or 0),
                        preview_url=theme.get("preview_url"),
                        accent_color=theme.get("accent_color"),
                        category=theme.get("category") or "premium",
                        access_type=theme.get("access_type") or "one_time",
                        duration_days=theme.get("duration_days"),
                        duration_label=theme.get("duration_label"),
                        event_starts_at=theme.get("event_starts_at"),
                        event_ends_at=theme.get("event_ends_at"),
                        event_label=theme.get("event_label"),
                        is_active=bool(theme.get("is_active", True)),
                        created_at=now_utc(),
                    )
                )
            else:
                # Mantém o catálogo embutido atualizado sem apagar compras dos usuários.
                conn.execute(
                    update(themes)
                    .where(themes.c.id == theme["id"])
                    .values(
                        name=theme["name"],
                        description=theme.get("description"),
                        price_cents=int(theme.get("price_cents") or 0),
                        preview_url=theme.get("preview_url"),
                        accent_color=theme.get("accent_color"),
                        category=theme.get("category") or "premium",
                        access_type=theme.get("access_type") or "one_time",
                        duration_days=theme.get("duration_days"),
                        duration_label=theme.get("duration_label"),
                        event_starts_at=theme.get("event_starts_at"),
                        event_ends_at=theme.get("event_ends_at"),
                        event_label=theme.get("event_label"),
                        is_active=bool(theme.get("is_active", True)),
                        updated_at=now_utc(),
                    )
                )


init_db()


# ==================================================
# DEPENDÊNCIAS
# ==================================================

def get_user_by_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Token ausente")

    raw_token = credentials.credentials
    hashed = token_hash(raw_token)

    with engine.begin() as conn:
        result = conn.execute(
            select(users, sessions.c.expires_at.label("session_expires_at"))
            .select_from(sessions.join(users, users.c.id == sessions.c.user_id))
            .where(sessions.c.token_hash == hashed)
        ).first()

        if result is None:
            raise HTTPException(status_code=401, detail="Token inválido")

        data = row_dict(result)
        expires_at = data.get("session_expires_at")
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at and expires_at <= now_utc():
            conn.execute(sessions.delete().where(sessions.c.token_hash == hashed))
            raise HTTPException(status_code=401, detail="Sessão expirada")

        banned_until = data.get("banned_until")
        if banned_until:
            if isinstance(banned_until, str):
                banned_until = datetime.fromisoformat(banned_until.replace("Z", "+00:00"))
            if banned_until.tzinfo is None:
                banned_until = banned_until.replace(tzinfo=timezone.utc)
            if banned_until <= now_utc():
                conn.execute(
                    update(users)
                    .where(users.c.id == data["id"])
                    .values(disabled=False, ban_level=None, ban_message=None, banned_until=None, updated_at=now_utc())
                )
                data["disabled"] = False
                data["ban_level"] = None
                data["ban_message"] = None
                data["banned_until"] = None

        if data.get("disabled"):
            message = data.get("ban_message") or "Conta banida/desativada pelo administrador."
            level = data.get("ban_level") or "banida"
            raise HTTPException(status_code=403, detail=f"Conta bloqueada ({level}). {message}")

        return data


def require_admin(user: Dict[str, Any] = Depends(get_user_by_token)) -> Dict[str, Any]:
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Acesso negado")
    return user


# ==================================================
# ROTAS BÁSICAS
# ==================================================

@app.get("/")
def home():
    return {
        "status": "online",
        "name": "PC Ultra Manager Server",
        "version": APP_VERSION,
        "database": "postgresql" if DATABASE_URL.startswith("postgresql") else "sqlite",
        "time": serialize_dt(now_utc()),
        "payment_provider": PAYMENT_PROVIDER,
        "mercadopago_configured": bool(MERCADOPAGO_ACCESS_TOKEN),
    }


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(select(func.count()).select_from(users)).scalar_one()
    return {"ok": True, "time": serialize_dt(now_utc())}


@app.get("/updates/check")
def check_updates(current_version: str = Query("")):
    return {
        "latest_version": APP_LATEST_VERSION,
        "current_version": current_version,
        "channel": APP_CHANNEL,
        "download_url": APP_DOWNLOAD_URL,
        "changelog": APP_CHANGELOG,
        "update_available": bool(APP_LATEST_VERSION and current_version and APP_LATEST_VERSION != current_version),
        "server_time": serialize_dt(now_utc()),
    }


@app.get("/activity/my")
def my_activity(user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        rows = conn.execute(
            select(app_logs).where(app_logs.c.user_id == user["id"]).order_by(app_logs.c.id.desc()).limit(100)
        ).fetchall()
    return {
        "activity": [
            {
                "id": row_dict(row).get("id"),
                "action": row_dict(row).get("action"),
                "details": row_dict(row).get("details"),
                "created_at": serialize_dt(row_dict(row).get("created_at")),
            }
            for row in rows
        ]
    }


@app.post("/support/tickets/create")
def create_support_ticket(data: SupportCreateRequest, user: Dict[str, Any] = Depends(get_user_by_token)):
    category = str(data.category or "bug").strip().casefold()[:60]
    priority = str(data.priority or "media").strip().casefold()[:30]
    with engine.begin() as conn:
        recent_tickets = int(conn.execute(
            select(func.count()).select_from(support_tickets).where(
                support_tickets.c.user_id == user["id"],
                support_tickets.c.created_at >= now_utc() - timedelta(minutes=10),
            )
        ).scalar_one() or 0)
        if recent_tickets >= 3:
            add_security_event(conn, "support_spam_blocked", False, user_id=user["id"], username=user.get("username"), details="Muitos tickets em 10 minutos")
            raise HTTPException(status_code=429, detail="Muitos tickets em pouco tempo. Aguarde alguns minutos.")
        result = conn.execute(
            support_tickets.insert().values(
                user_id=user["id"],
                category=category,
                priority=priority,
                title=str(data.title).strip()[:180],
                message=safe_details(data.message),
                status="aberto",
                created_at=now_utc(),
                updated_at=now_utc(),
            )
        )
        ticket_id = result.inserted_primary_key[0]
        add_app_log(conn, user["id"], "support_ticket_created", f"ticket=#{ticket_id}; {data.title}")
    return {"message": "Ticket enviado para o suporte", "ticket_id": ticket_id}


@app.get("/support/tickets/my")
def my_support_tickets(user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        rows = conn.execute(
            select(support_tickets).where(support_tickets.c.user_id == user["id"]).order_by(support_tickets.c.id.desc()).limit(100)
        ).fetchall()
    return {"tickets": [serialize_ticket(row) for row in rows]}


# ==================================================
# ROTAS DE BETA FECHADA
# ==================================================

@app.get("/beta/access-plans")
def beta_access_plans():
    return beta_access_catalog_public()


@app.post("/beta/access-orders/create")
def create_beta_access_order(data: CreateBetaAccessOrderRequest):
    option = find_beta_access_option(data.option_name, data.expires_days, data.permanent, data.price_cents)
    if int(option["price_cents"]) <= 0:
        raise HTTPException(status_code=400, detail="Valor beta inválido")

    if not mercadopago_enabled():
        raise HTTPException(status_code=503, detail="Mercado Pago não configurado para compra automática de Acesso Antecipado Beta")

    order_token = secrets.token_urlsafe(28)
    buyer_name = str(data.buyer_name or "Beta Tester").strip()[:120] or "Beta Tester"
    buyer_email = valid_email_or_technical(data.buyer_email, buyer_name)
    with engine.begin() as conn:
        result = conn.execute(
            beta_access_orders.insert().values(
                order_token=order_token,
                buyer_name=buyer_name,
                buyer_email=buyer_email,
                device_id=str(data.device_id or "")[:500],
                option_name=option["option_name"],
                duration_label=option["duration_label"],
                expires_days=option.get("expires_days"),
                permanent=bool(option.get("permanent")),
                price_cents=int(option["price_cents"]),
                status="payment_pending",
                payment_provider="mercadopago",
                payment_status="pending",
                created_at=now_utc(),
            )
        )
        order_id = result.inserted_primary_key[0]

    payment_payload = create_mp_pix_payment_public(
        external_reference=f"beta:{order_id}",
        amount_cents=int(option["price_cents"]),
        description=f"PC Ultra Manager - Acesso Antecipado Beta {option['duration_label']}",
        payer_email=buyer_email,
        payer_name=buyer_name,
        idempotency_prefix=f"beta-order-{order_id}",
    )

    with engine.begin() as conn:
        conn.execute(
            update(beta_access_orders)
            .where(beta_access_orders.c.id == order_id)
            .values(
                payment_id=payment_payload.get("payment_id"),
                payment_status=payment_payload.get("payment_status"),
                payment_qr_code=payment_payload.get("payment_qr_code"),
                payment_qr_code_base64=payment_payload.get("payment_qr_code_base64"),
                payment_ticket_url=payment_payload.get("payment_ticket_url"),
                payment_created_at=now_utc(),
            )
        )

    return {
        "message": "PIX do Acesso Antecipado Beta criado. Pague para receber a key beta automaticamente.",
        "order_id": order_id,
        "order_token": order_token,
        "status": "payment_pending",
        "title": "Acesso Antecipado Beta",
        "option_name": option["option_name"],
        "duration_label": option["duration_label"],
        "expires_days": option.get("expires_days"),
        "permanent": bool(option.get("permanent")),
        "price_cents": option["price_cents"],
        "price_label": price_label(option["price_cents"]),
        **payment_payload,
    }


@app.get("/beta/access-orders/{order_id}/status")
def beta_access_order_status(order_id: int, token: str = Query(...)):
    with engine.connect() as conn:
        found = conn.execute(
            select(beta_access_orders).where(beta_access_orders.c.id == order_id, beta_access_orders.c.order_token == str(token))
        ).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido beta não encontrado")
        order = row_dict(found)
    if order.get("payment_provider") == "mercadopago" and order.get("payment_id") and order.get("status") != "delivered":
        return sync_mp_payment_for_beta_order(order_id, token)
    return {"order": serialize_beta_access_order(order), "payment_checked": False}


@app.post("/beta/verify")
def verify_beta_key(data: VerifyBetaRequest):
    beta_plain = str(data.key or "").strip()
    if not beta_plain:
        raise HTTPException(status_code=400, detail="Key beta ausente")

    with engine.begin() as conn:
        found = conn.execute(select(beta_keys).where(beta_keys.c.key_hash == hash_text(beta_plain))).first()
        if not found:
            raise HTTPException(status_code=404, detail="Key beta inválida")

        beta = row_dict(found)
        info = serialize_beta_key(beta)
        if info["revoked"]:
            raise HTTPException(status_code=403, detail=beta.get("message") or "Key beta revogada pelo administrador.")
        if info["expired"]:
            raise HTTPException(status_code=403, detail="Key beta expirada.")
        if not info["available"]:
            raise HTTPException(status_code=403, detail="Limite de uso da key beta atingido.")

        current_uses = int(beta.get("current_uses") or 0) + 1
        conn.execute(
            update(beta_keys)
            .where(beta_keys.c.id == beta["id"])
            .values(current_uses=current_uses, last_used_at=now_utc())
        )
        add_app_log(
            conn,
            None,
            "beta_verified",
            f"key={beta.get('display_name')}; device={str(data.device_id or '')[:120]}; version={str(data.app_version or '')[:40]}",
        )

    return {
        "allowed": True,
        "message": beta.get("message") or "Acesso liberado para a Beta Final fechada.",
        "display_name": beta.get("display_name"),
        "access_level": beta.get("access_level") or "closed_beta",
        "remaining_uses": max(0, int(beta.get("max_uses") or 0) - current_uses) if int(beta.get("max_uses") or 0) > 0 else None,
        "expires_at": serialize_dt(beta.get("expires_at")),
        "server_time": serialize_dt(now_utc()),
    }


@app.post("/admin/beta-keys/create")
def admin_create_beta_key(data: CreateBetaKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    key_plain = str(data.key_code or "").strip()
    if len(key_plain) < 3:
        raise HTTPException(status_code=400, detail="Key beta muito curta")
    expires_at = None
    if data.expires_days is not None and int(data.expires_days) > 0:
        expires_at = now_utc() + timedelta(days=int(data.expires_days))
    with engine.begin() as conn:
        try:
            conn.execute(
                beta_keys.insert().values(
                    key_hash=hash_text(key_plain),
                    display_name=str(data.display_name).strip(),
                    access_level=str(data.access_level or "closed_beta").strip(),
                    max_uses=max(0, int(data.max_uses or 1)),
                    current_uses=0,
                    revoked=False,
                    message=data.message or "Acesso liberado para a Beta Final fechada.",
                    expires_at=expires_at,
                    created_by=admin["id"],
                    created_at=now_utc(),
                )
            )
        except IntegrityError:
            raise HTTPException(status_code=400, detail="Key beta já existe")
        add_admin_log(conn, admin["id"], "beta_key_create", data.display_name, f"max_uses={data.max_uses}; expires={serialize_dt(expires_at)}")
    return {"message": "Key beta criada no servidor", "key_code": key_plain, "display_name": data.display_name, "expires_at": serialize_dt(expires_at)}


@app.get("/admin/beta-keys")
def admin_list_beta_keys(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(beta_keys).order_by(beta_keys.c.id.desc()).limit(300)).fetchall()
    return {"beta_keys": [serialize_beta_key(row) for row in rows]}


@app.post("/admin/beta-keys/revoke")
def admin_revoke_beta_key(data: BetaKeyActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    with engine.begin() as conn:
        query = select(beta_keys)
        if data.key_id is not None:
            query = query.where(beta_keys.c.id == int(data.key_id))
        elif data.key_code:
            query = query.where(beta_keys.c.key_hash == hash_text(data.key_code))
        else:
            raise HTTPException(status_code=400, detail="Informe key_id ou key_code")
        found = conn.execute(query).first()
        if not found:
            raise HTTPException(status_code=404, detail="Key beta não encontrada")
        beta = row_dict(found)
        conn.execute(update(beta_keys).where(beta_keys.c.id == beta["id"]).values(revoked=True))
        add_admin_log(conn, admin["id"], "beta_key_revoke", beta.get("display_name"), f"id={beta['id']}")
    return {"message": "Key beta revogada", "id": beta["id"]}


@app.post("/admin/beta-keys/delete")
def admin_delete_beta_key(data: BetaKeyActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    with engine.begin() as conn:
        query = select(beta_keys)
        if data.key_id is not None:
            query = query.where(beta_keys.c.id == int(data.key_id))
        elif data.key_code:
            query = query.where(beta_keys.c.key_hash == hash_text(data.key_code))
        else:
            raise HTTPException(status_code=400, detail="Informe key_id ou key_code")
        found = conn.execute(query).first()
        if not found:
            raise HTTPException(status_code=404, detail="Key beta não encontrada")
        beta = row_dict(found)
        conn.execute(beta_keys.delete().where(beta_keys.c.id == beta["id"]))
        add_admin_log(conn, admin["id"], "beta_key_delete", beta.get("display_name"), f"id={beta['id']}")
    return {"message": "Key beta excluída", "id": beta["id"]}


# ==================================================
# ROTAS DE CONTA
# ==================================================

@app.post("/auth/register")
def register(data: RegisterRequest):
    username = normalize_username(data.username)
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Nome muito curto")

    recovery_key = "REC-" + secrets.token_hex(8).upper()

    with engine.begin() as conn:
        try:
            conn.execute(
                users.insert().values(
                    username=username,
                    password_hash=password_hash(data.password),
                    recovery_key_hash=hash_text(recovery_key),
                    role="user",
                    plan="free",
                    permanent=False,
                    created_at=now_utc(),
                )
            )
        except IntegrityError:
            raise HTTPException(status_code=400, detail="Usuário já existe")

    return {
        "message": "Conta criada com sucesso",
        "username": username,
        "recovery_key": recovery_key,
        "plan": "free",
    }


@app.post("/auth/login")
def login(data: LoginRequest):
    username = normalize_username(data.username)

    with engine.begin() as conn:
        if recent_security_count(conn, "login_failed", username=username, minutes=15) >= 5:
            add_security_event(conn, "login_blocked", False, username=username, details="Muitas tentativas de login em 15 minutos")
            raise HTTPException(status_code=429, detail="Muitas tentativas de login. Aguarde 15 minutos e tente novamente.")

        found = conn.execute(select(users).where(users.c.username == username)).first()
        if not found:
            add_security_event(conn, "login_failed", False, username=username, details="Usuário inexistente")
            raise HTTPException(status_code=401, detail="Login inválido")

        user = row_dict(found)
        banned_until = user.get("banned_until")
        if banned_until:
            if isinstance(banned_until, str):
                banned_until = datetime.fromisoformat(banned_until.replace("Z", "+00:00"))
            if banned_until.tzinfo is None:
                banned_until = banned_until.replace(tzinfo=timezone.utc)
            if banned_until <= now_utc():
                conn.execute(
                    update(users)
                    .where(users.c.id == user["id"])
                    .values(disabled=False, ban_level=None, ban_message=None, banned_until=None, updated_at=now_utc())
                )
                user["disabled"] = False
                user["ban_level"] = None
                user["ban_message"] = None
                user["banned_until"] = None

        if user.get("disabled"):
            message = user.get("ban_message") or "Conta banida/desativada pelo administrador."
            level = user.get("ban_level") or "banida"
            banned_until = user.get("banned_until")
            add_security_event(conn, "login_blocked_banned", False, user_id=user["id"], username=username, details=f"level={level}")
            raise HTTPException(status_code=403, detail=f"Conta bloqueada ({level}). {message}" + (f" Até: {serialize_dt(banned_until)}" if banned_until else ""))

        if not verify_password(data.password, user["password_hash"]):
            add_security_event(conn, "login_failed", False, user_id=user["id"], username=username, details="Senha incorreta")
            raise HTTPException(status_code=401, detail="Login inválido")

        # Atualiza senha antiga SHA256 para PBKDF2 no primeiro login correto.
        if not user["password_hash"].startswith("pbkdf2_sha256$"):
            conn.execute(update(users).where(users.c.id == user["id"]).values(password_hash=password_hash(data.password)))

        raw_token = secrets.token_urlsafe(48)
        conn.execute(
            sessions.insert().values(
                token_hash=token_hash(raw_token),
                user_id=user["id"],
                created_at=now_utc(),
                expires_at=now_utc() + timedelta(days=SESSION_DAYS),
            )
        )

        payload = user_license_payload(user)
        add_security_event(conn, "login_success", True, user_id=user["id"], username=username, details="Login realizado")
        add_app_log(conn, user["id"], "login_success", "Login realizado no app")

    return {
        "message": "Login realizado",
        "token": raw_token,
        "username": user["username"],
        "role": user.get("role", "user"),
        "plan": payload["plan"],
        "premium_active": payload["premium_active"],
        "premium_until": payload["premium_until"],
        "permanent": payload["permanent"],
    }


@app.post("/auth/recover")
def recover_account(data: RecoverRequest):
    username = normalize_username(data.username)

    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.username == username)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        user = row_dict(found)
        if user["recovery_key_hash"] != hash_text(data.recovery_key):
            raise HTTPException(status_code=401, detail="Key de recuperação inválida")

        conn.execute(
            update(users)
            .where(users.c.id == user["id"])
            .values(password_hash=password_hash(data.new_password), updated_at=now_utc())
        )

    return {"message": "Conta recuperada com sucesso", "username": username}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_user_by_token)):
    payload = user_license_payload(user)
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user.get("role", "user"),
        "plan": payload["plan"],
        "plan_name": payload["plan_name"],
        "premium_until": payload["premium_until"],
        "permanent": payload["permanent"],
        "created_at": serialize_dt(user.get("created_at")),
    }


# ==================================================
# ROTAS DE LICENÇA / PREMIUM
# ==================================================

@app.post("/license/activate")
def activate_license(data: ActivateKeyRequest, user: Dict[str, Any] = Depends(get_user_by_token)):
    key_plain = str(data.key or "").strip()
    if not key_plain:
        raise HTTPException(status_code=400, detail="Key ausente")

    with engine.begin() as conn:
        if recent_security_count(conn, "license_invalid", user_id=user["id"], minutes=15) >= 5:
            add_security_event(conn, "license_blocked", False, user_id=user["id"], username=user.get("username"), details="Muitas tentativas de key inválida")
            raise HTTPException(status_code=429, detail="Muitas tentativas de key inválida. Aguarde alguns minutos.")

        found = conn.execute(select(license_keys).where(license_keys.c.key_code_hash == hash_text(key_plain))).first()
        if not found:
            add_security_event(conn, "license_invalid", False, user_id=user["id"], username=user.get("username"), details="Key inexistente")
            raise HTTPException(status_code=404, detail="Key inválida")

        key = row_dict(found)
        if key.get("revoked"):
            add_security_event(conn, "license_invalid", False, user_id=user["id"], username=user.get("username"), details="Key revogada")
            raise HTTPException(status_code=400, detail="Key revogada")
        if key.get("is_used"):
            add_security_event(conn, "license_invalid", False, user_id=user["id"], username=user.get("username"), details="Key já usada")
            raise HTTPException(status_code=400, detail="Key já usada")

        plan = normalize_plan(key["plan"])
        permanent = bool(key.get("permanent")) or key.get("duration_minutes") in (None, 0, -1)
        expires_at = None if permanent else now_utc() + timedelta(minutes=int(key["duration_minutes"]))

        conn.execute(
            update(users)
            .where(users.c.id == user["id"])
            .values(plan=plan, premium_until=expires_at, permanent=permanent, updated_at=now_utc())
        )
        conn.execute(
            update(license_keys)
            .where(license_keys.c.id == key["id"])
            .values(is_used=True, used_by=user["id"], used_at=now_utc())
        )
        add_app_log(conn, user["id"], "license_activated", f"{key['display_name']} -> {plan}")

    return {
        "message": "Key ativada com sucesso",
        "key_name": key["display_name"],
        "plan": plan,
        "plan_name": public_plan_name(plan),
        "duration_minutes": key.get("duration_minutes"),
        "expires_at": serialize_dt(expires_at),
        "premium_until": serialize_dt(expires_at),
        "permanent": permanent,
    }


@app.get("/license/status")
def license_status(user: Dict[str, Any] = Depends(get_user_by_token)):
    payload = user_license_payload(user)

    # Se expirou, já normaliza no banco para Free.
    if payload["expired"]:
        with engine.begin() as conn:
            conn.execute(
                update(users)
                .where(users.c.id == user["id"])
                .values(plan="free", premium_until=None, permanent=False, updated_at=now_utc())
            )
            add_app_log(conn, user["id"], "license_expired", "Plano expirado e normalizado para Free")
        payload["premium_until"] = None
        payload["expires_at"] = None

    return payload


# ==================================================
# ROTAS DE PLANOS / PEDIDOS
# ==================================================

@app.get("/plans")
def list_plans():
    return public_catalog()


def serialize_order(row: Any) -> Dict[str, Any]:
    data = row_dict(row)
    return {
        "id": data.get("id"),
        "user_id": data.get("user_id"),
        "plan": data.get("plan"),
        "plan_title": data.get("plan_title"),
        "option_name": data.get("option_name"),
        "duration_label": data.get("duration_label"),
        "duration_minutes": data.get("duration_minutes"),
        "permanent": bool(data.get("permanent")),
        "price_cents": data.get("price_cents"),
        "price_label": price_label(int(data.get("price_cents") or 0)),
        "status": data.get("status"),
        "user_message": data.get("user_message"),
        "admin_message": data.get("admin_message"),
        "created_at": serialize_dt(data.get("created_at")),
        "approved_at": serialize_dt(data.get("approved_at")),
        "approved_by": data.get("approved_by"),
        "delivered_at": serialize_dt(data.get("delivered_at")),
        "cancelled_at": serialize_dt(data.get("cancelled_at")),
        "payment_provider": data.get("payment_provider"),
        "payment_id": data.get("payment_id"),
        "payment_status": data.get("payment_status"),
        "payment_qr_code": data.get("payment_qr_code"),
        "payment_qr_code_base64": data.get("payment_qr_code_base64"),
        "payment_ticket_url": data.get("payment_ticket_url"),
        "payment_created_at": serialize_dt(data.get("payment_created_at")),
        "payment_paid_at": serialize_dt(data.get("payment_paid_at")),
    }



def mercadopago_enabled() -> bool:
    return PAYMENT_PROVIDER == "mercadopago" and bool(MERCADOPAGO_ACCESS_TOKEN)


def mp_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
    if not MERCADOPAGO_ACCESS_TOKEN:
        raise HTTPException(status_code=500, detail="Mercado Pago não configurado no servidor")
    url = f"https://api.mercadopago.com{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {MERCADOPAGO_ACCESS_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if idempotency_key:
        headers["X-Idempotency-Key"] = idempotency_key
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Mercado Pago erro {exc.code}: {detail[:800]}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Falha ao comunicar com Mercado Pago: {exc}")




def parse_mp_signature_header(signature_header: str) -> Dict[str, str]:
    parts: Dict[str, str] = {}
    for item in str(signature_header or "").split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key.strip()] = value.strip()
    return parts


def verify_mp_webhook_signature(request: Request, payment_id: Optional[str]) -> bool:
    """Valida x-signature do Mercado Pago quando MERCADOPAGO_WEBHOOK_SECRET está configurado."""
    if not MERCADOPAGO_WEBHOOK_SECRET:
        return True

    signature_header = request.headers.get("x-signature", "")
    request_id = request.headers.get("x-request-id", "")
    parts = parse_mp_signature_header(signature_header)
    ts = parts.get("ts")
    received_hash = parts.get("v1")
    if not ts or not received_hash:
        return False

    data_id = request.query_params.get("data.id") or request.query_params.get("id")
    if data_id:
        data_id = str(data_id).lower()
    elif payment_id and request.query_params.get("data.id"):
        data_id = str(payment_id).lower()

    manifest = ""
    if data_id:
        manifest += f"id:{data_id};"
    if request_id:
        manifest += f"request-id:{request_id};"
    manifest += f"ts:{ts};"

    expected_hash = hmac.new(
        MERCADOPAGO_WEBHOOK_SECRET.encode("utf-8"),
        msg=manifest.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash):
        return False

    try:
        timestamp = int(ts)
        if timestamp > 9_999_999_999:
            timestamp = timestamp // 1000
        age = abs(datetime.now(timezone.utc).timestamp() - timestamp)
        if age > MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS:
            return False
    except Exception:
        return False

    return True


def mp_amount_to_cents(value: Any) -> Optional[int]:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    cents = (amount * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(cents)


def mp_payment_matches_order(payment: Dict[str, Any], order: Dict[str, Any], expected_reference: str) -> Tuple[bool, str]:
    """Confere se o pagamento consultado pertence ao pedido e tem valor correto antes de entregar."""
    if str(payment.get("external_reference") or "") != str(expected_reference):
        return False, "external_reference diferente do pedido"

    stored_payment_id = str(order.get("payment_id") or "")
    received_payment_id = str(payment.get("id") or "")
    if stored_payment_id and received_payment_id and stored_payment_id != received_payment_id:
        return False, "payment_id diferente do pedido salvo"

    method = str(payment.get("payment_method_id") or "").strip().casefold()
    if method and method != "pix":
        return False, "método de pagamento não é PIX"

    paid_cents = mp_amount_to_cents(payment.get("transaction_amount"))
    expected_cents = int(order.get("price_cents") or 0)
    if paid_cents is None or paid_cents != expected_cents:
        return False, f"valor pago incompatível: recebido={paid_cents}; esperado={expected_cents}"

    return True, "pagamento validado"


def mp_payment_is_approved(status: str) -> bool:
    return str(status or "").casefold() in {"approved", "accredited"}

def make_mp_payer_email(user: Dict[str, Any]) -> str:
    """Mercado Pago exige um payer.email em formato público válido.

    O app hoje usa username, não e-mail. Por isso geramos um e-mail técnico
    válido e estável por usuário. Nunca use .local, porque o Mercado Pago rejeita.
    """
    raw_username = str(user.get("username") or "usuario").strip().lower()
    local = re.sub(r"[^a-z0-9._+-]+", ".", raw_username).strip("._+-")
    if not local:
        local = "usuario"
    local = local[:40]
    user_id = str(user.get("id") or secrets.token_hex(4))
    domain = MERCADOPAGO_PAYER_EMAIL_DOMAIN
    if "." not in domain or "@" in domain:
        domain = "pcultramanager.com.br"
    return f"{local}.{user_id}@{domain}"


def valid_email_or_technical(email: Optional[str], fallback_name: str = "beta") -> str:
    candidate = str(email or "").strip().lower()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
        return candidate[:180]
    local = re.sub(r"[^a-z0-9._+-]+", ".", str(fallback_name or "cliente").strip().lower()).strip("._+-") or "cliente"
    if "." not in MERCADOPAGO_PAYER_EMAIL_DOMAIN or "@" in MERCADOPAGO_PAYER_EMAIL_DOMAIN:
        domain = "pcultramanager.com.br"
    else:
        domain = MERCADOPAGO_PAYER_EMAIL_DOMAIN
    return f"{local[:36]}.{secrets.token_hex(3)}@{domain}"


def is_valid_public_email(email: Optional[str]) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(email or "").strip().lower()))


def transactional_email_configured() -> bool:
    return bool(EMAIL_ENABLED and SMTP_HOST and SMTP_FROM_EMAIL)


def format_money_br(cents: Any) -> str:
    try:
        return price_label(int(cents or 0))
    except Exception:
        return "R$ 0,00"


def format_dt_br(value: Any) -> str:
    dt = normalize_dt(value)
    if not dt:
        return "Não informado"
    br_tz = timezone(timedelta(hours=-3), "BRT")
    return dt.astimezone(br_tz).strftime("%d/%m/%Y às %H:%M") + " (horário de Brasília)"


def send_transactional_email(to_email: str, subject: str, text_body: str, html_body: Optional[str] = None) -> Tuple[bool, str]:
    if not transactional_email_configured():
        return False, "SMTP não configurado. Defina EMAIL_ENABLED=true e SMTP_* no Render."
    if not is_valid_public_email(to_email):
        return False, "E-mail do comprador inválido."

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((SMTP_FROM_NAME, SMTP_FROM_EMAIL))
    msg["To"] = to_email
    if SMTP_SUPPORT_EMAIL and is_valid_public_email(SMTP_SUPPORT_EMAIL):
        msg["Reply-To"] = SMTP_SUPPORT_EMAIL
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if SMTP_USE_SSL:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=30) as smtp:
                if SMTP_USERNAME:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
                if SMTP_USE_STARTTLS:
                    smtp.starttls(context=ssl.create_default_context())
                if SMTP_USERNAME:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(msg)
        return True, "E-mail enviado com sucesso."
    except Exception as exc:
        return False, f"Falha ao enviar e-mail: {str(exc)[:500]}"


def build_theme_receipt_email(order: Dict[str, Any], username: str) -> Tuple[str, str, str]:
    """Monta um e-mail premium de comprovante/tutorial para compras de temas.

    O e-mail tem três funções claras:
    1. comprovante para emergência/suporte;
    2. tutorial de ativação no app;
    3. agradecimento com validade, quando o item for assinatura/evento temporário.
    """
    theme_id = str(order.get("theme_id") or "").strip()
    theme_name = str(order.get("theme_name") or theme_id or "Tema")
    buyer_name = str(order.get("buyer_name") or username or "cliente").strip() or "cliente"
    order_id = order.get("id")
    payment_id = order.get("payment_id") or "Não informado"
    access_type = str(order.get("access_type") or "one_time").casefold()
    is_subscription = access_type == "subscription" or theme_id == "matrix_effect_subscription"
    is_event_sale_permanent = theme_id == "diamond_black_event" or theme_id in WEEKLY_EVENT_THEME_IDS or access_type in {"event_sale", "weekly_event_sale"}
    is_weekly_or_event = access_type in {"weekly_free", "event", "weekly_event"} and not is_event_sale_permanent
    started_at = order.get("delivered_at") or order.get("payment_paid_at") or now_utc()
    expires_at = order.get("access_expires_at")

    if is_subscription:
        readable_type = "Assinatura mensal"
        title_type = "Assinatura ativada"
        validity = format_dt_br(expires_at) if expires_at else "30 dias após a aprovação do pagamento"
        next_action = "Renove antes do vencimento para continuar usando este tema sem interrupção."
    elif is_event_sale_permanent:
        readable_type = "Tema de evento semanal — compra permanente"
        title_type = "Tema de evento comprado"
        validity = "Permanente na conta. O evento semanal controla apenas o período em que o tema aparece na loja para compra."
        next_action = "Mesmo quando o evento semanal sair da loja, este tema continuará liberado para você no app, desde que entre na mesma conta."
    elif is_weekly_or_event:
        readable_type = "Tema semanal temporário"
        title_type = "Tema semanal liberado"
        validity = format_dt_br(expires_at) if expires_at else "Enquanto a regra semanal estiver ativa"
        next_action = "Quando a regra semanal terminar, o acesso poderá ser bloqueado se o tema não tiver sido comprado permanentemente."
    else:
        readable_type = "Compra vitalícia"
        title_type = "Tema liberado"
        validity = "Vitalício na conta, salvo violação de regra, reembolso ou remoção administrativa justificada"
        next_action = "O tema continua liberado na sua conta mesmo após fechar ou reinstalar o app, desde que você faça login na mesma conta."

    order_hash_raw = f"theme:{order_id}:{theme_id}:{payment_id}:{order.get('user_id')}"
    receipt_code = hashlib.sha256(order_hash_raw.encode("utf-8", "ignore")).hexdigest()[:12].upper()
    support_email = SMTP_SUPPORT_EMAIL if is_valid_public_email(SMTP_SUPPORT_EMAIL) else SMTP_FROM_EMAIL

    subject = f"Comprovante e ativação: {theme_name} — PC Ultra Manager"

    # HTML-safe values
    h_theme_name = html.escape(theme_name)
    h_buyer_name = html.escape(buyer_name)
    h_username = html.escape(str(username or ""))
    h_payment_id = html.escape(str(payment_id or ""))
    h_validity = html.escape(str(validity or ""))
    h_started_at = html.escape(format_dt_br(started_at))
    h_value = html.escape(format_money_br(order.get('price_cents')))
    h_type = html.escape(readable_type)
    h_receipt_code = html.escape(receipt_code)
    h_next_action = html.escape(next_action)
    h_support_email = html.escape(str(support_email or ""))

    text_body = f"""Olá, {buyer_name}!

Pagamento aprovado. O tema {theme_name} foi liberado na sua conta do PC Ultra Manager.

COMPROVANTE PARA EMERGÊNCIAS
Código do comprovante: {receipt_code}
Pedido: #{order_id}
Tema: {theme_name}
Conta do app/site: {username}
Valor pago: {format_money_br(order.get('price_cents'))}
Tipo: {readable_type}
Status: aprovado e entregue
ID do pagamento: {payment_id}
Data da ativação: {format_dt_br(started_at)}
Validade: {validity}

COMO ATIVAR O TEMA NO APP
1. Abra o PC Ultra Manager.
2. Faça login com a mesma conta usada na compra: {username}.
3. Entre na aba Loja de Temas.
4. Clique em Sincronizar compras.
5. Localize o tema {theme_name}.
6. Clique em Aplicar tema.

SE NÃO APARECER NO APP
1. Confirme se você está logado na mesma conta da compra.
2. Clique novamente em Sincronizar compras.
3. Feche e abra o app.
4. Guarde este e-mail e envie o código {receipt_code} ao suporte, se precisar.

OBSERVAÇÃO SOBRE VALIDADE
{next_action}

SUPORTE
E-mail de suporte: {support_email or 'não configurado'}

Obrigado por apoiar o PC Ultra Manager.
Sua compra ajuda a manter o projeto vivo, mais bonito, mais seguro e mais profissional.

PC Ultra Manager
"""

    html_body = f"""
<!doctype html>
<html lang="pt-BR">
<body style="margin:0;background:#05070d;color:#f8fafc;font-family:Arial,Helvetica,sans-serif;">
  <div style="max-width:760px;margin:0 auto;padding:28px;">
    <div style="border:1px solid rgba(248,250,252,.18);border-radius:28px;padding:0;background:linear-gradient(135deg,rgba(15,23,42,.98),rgba(2,6,23,.98));box-shadow:0 28px 80px rgba(0,0,0,.52);overflow:hidden;">
      <div style="padding:28px;background:radial-gradient(circle at 20% 0%,rgba(125,211,252,.20),transparent 34%),radial-gradient(circle at 82% 8%,rgba(185,154,91,.20),transparent 32%);border-bottom:1px solid rgba(255,255,255,.10);">
        <p style="margin:0 0 8px;color:#93c5fd;font-size:12px;letter-spacing:.16em;text-transform:uppercase;">PC Ultra Manager • Loja de Temas</p>
        <h1 style="margin:0 0 10px;font-size:30px;line-height:1.18;color:#ffffff;">{html.escape(title_type)}: {h_theme_name}</h1>
        <p style="margin:0;color:#cbd5e1;line-height:1.6;">Olá, <b>{h_buyer_name}</b>. Seu pagamento foi aprovado e o tema foi liberado na conta <b>{h_username}</b>.</p>
      </div>

      <div style="padding:28px;">
        <div style="border:1px solid rgba(255,255,255,.14);border-radius:20px;padding:20px;margin:0 0 18px;background:rgba(255,255,255,.055);">
          <h2 style="margin:0 0 14px;font-size:19px;color:#ffffff;">Comprovante para emergências</h2>
          <table style="width:100%;border-collapse:collapse;color:#e2e8f0;font-size:14px;">
            <tr><td style="padding:7px 0;color:#94a3b8;">Código</td><td style="padding:7px 0;text-align:right;"><b>{h_receipt_code}</b></td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Pedido</td><td style="padding:7px 0;text-align:right;">#{order_id}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Tema</td><td style="padding:7px 0;text-align:right;">{h_theme_name}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Conta</td><td style="padding:7px 0;text-align:right;">{h_username}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Valor pago</td><td style="padding:7px 0;text-align:right;">{h_value}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Tipo</td><td style="padding:7px 0;text-align:right;">{h_type}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">ID Mercado Pago</td><td style="padding:7px 0;text-align:right;">{h_payment_id}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Ativação</td><td style="padding:7px 0;text-align:right;">{h_started_at}</td></tr>
            <tr><td style="padding:7px 0;color:#94a3b8;">Validade</td><td style="padding:7px 0;text-align:right;"><b>{h_validity}</b></td></tr>
          </table>
        </div>

        <div style="border:1px solid rgba(125,211,252,.24);border-radius:20px;padding:20px;margin:18px 0;background:rgba(14,165,233,.08);">
          <h2 style="margin:0 0 14px;font-size:19px;color:#ffffff;">Como ativar no app</h2>
          <ol style="line-height:1.9;color:#e2e8f0;margin:0;padding-left:22px;">
            <li>Abra o <b>PC Ultra Manager</b>.</li>
            <li>Faça login com a mesma conta da compra: <b>{h_username}</b>.</li>
            <li>Entre na aba <b>Loja de Temas</b>.</li>
            <li>Clique em <b>Sincronizar compras</b>.</li>
            <li>Localize <b>{h_theme_name}</b> e clique em <b>Aplicar tema</b>.</li>
          </ol>
        </div>

        <div style="border:1px solid rgba(185,154,91,.28);border-radius:20px;padding:18px;margin:18px 0;background:rgba(185,154,91,.08);">
          <h2 style="margin:0 0 10px;font-size:18px;color:#ffffff;">Validade e suporte</h2>
          <p style="margin:0 0 12px;color:#e2e8f0;line-height:1.65;">{h_next_action}</p>
          <p style="margin:0;color:#cbd5e1;line-height:1.65;">Guarde este e-mail. Em caso de suporte, informe o código <b>{h_receipt_code}</b>{' para ' + h_support_email if h_support_email else ''}.</p>
        </div>

        <p style="margin:22px 0 0;color:#f8fafc;line-height:1.6;"><b>Obrigado por apoiar o PC Ultra Manager.</b><br>Sua compra ajuda a manter o projeto vivo, mais bonito, mais seguro e mais profissional.</p>
      </div>
    </div>
  </div>
</body>
</html>
"""
    return subject, text_body, html_body


def send_theme_receipt_email(conn, order: Dict[str, Any]) -> Dict[str, Any]:
    buyer_email = str(order.get("buyer_email") or "").strip().lower()
    if not buyer_email:
        return {"sent": False, "reason": "Pedido sem e-mail do comprador."}
    if not is_valid_public_email(buyer_email):
        conn.execute(update(theme_orders).where(theme_orders.c.id == int(order["id"])).values(receipt_email_error="E-mail inválido para envio de comprovante."))
        return {"sent": False, "reason": "E-mail inválido."}
    if order.get("receipt_email_sent_at"):
        return {"sent": False, "already_sent": True, "sent_at": serialize_dt(order.get("receipt_email_sent_at"))}

    user_row = conn.execute(select(users.c.username).where(users.c.id == int(order["user_id"]))).first()
    username = row_dict(user_row).get("username") if user_row else str(order.get("user_id"))
    subject, text_body, html_body = build_theme_receipt_email(order, str(username or "usuário"))
    sent, message = send_transactional_email(buyer_email, subject, text_body, html_body)
    if sent:
        conn.execute(update(theme_orders).where(theme_orders.c.id == int(order["id"])).values(receipt_email_sent_at=now_utc(), receipt_email_error=None))
        add_app_log(conn, int(order["user_id"]), "theme_receipt_email_sent", f"pedido_tema={order['id']}; theme={order.get('theme_id')}; email={buyer_email}")
        return {"sent": True, "email": buyer_email}
    conn.execute(update(theme_orders).where(theme_orders.c.id == int(order["id"])).values(receipt_email_error=message[:1000]))
    add_app_log(conn, int(order["user_id"]), "theme_receipt_email_failed", f"pedido_tema={order['id']}; theme={order.get('theme_id')}; email={buyer_email}; {message}")
    return {"sent": False, "email": buyer_email, "reason": message}


def create_mp_pix_payment_public(external_reference: str, amount_cents: int, description: str, payer_email: str, payer_name: str, idempotency_prefix: str) -> Dict[str, Any]:
    amount = round(int(amount_cents) / 100, 2)
    payload = {
        "transaction_amount": amount,
        "description": str(description or "PC Ultra Manager")[:250],
        "payment_method_id": "pix",
        "external_reference": str(external_reference),
        "payer": {"email": payer_email, "first_name": str(payer_name or "Cliente")[:60]},
        "notification_url": f"{PUBLIC_BASE_URL}/payments/mercadopago/webhook",
    }
    payment = mp_request("POST", "/v1/payments", payload, idempotency_key=f"{idempotency_prefix}-{secrets.token_hex(8)}")
    tx = (payment.get("point_of_interaction") or {}).get("transaction_data") or {}
    return {
        "payment_id": str(payment.get("id") or ""),
        "payment_status": payment.get("status") or "pending",
        "payment_qr_code": tx.get("qr_code"),
        "payment_qr_code_base64": tx.get("qr_code_base64"),
        "payment_ticket_url": tx.get("ticket_url"),
    }


def create_mp_pix_payment(order_id: int, user: Dict[str, Any], option: Dict[str, Any], plan: str) -> Dict[str, Any]:
    amount = round(int(option["price_cents"]) / 100, 2)
    description = f"PC Ultra Manager - {public_plan_name(plan)} {option['duration_label']}"
    payer_email = make_mp_payer_email(user)
    payload = {
        "transaction_amount": amount,
        "description": description[:250],
        "payment_method_id": "pix",
        "external_reference": str(order_id),
        "payer": {"email": payer_email, "first_name": str(user.get("username") or "Cliente")[:60]},
        "notification_url": f"{PUBLIC_BASE_URL}/payments/mercadopago/webhook",
    }
    payment = mp_request("POST", "/v1/payments", payload, idempotency_key=f"order-{order_id}-{secrets.token_hex(8)}")
    tx = (payment.get("point_of_interaction") or {}).get("transaction_data") or {}
    return {
        "payment_id": str(payment.get("id") or ""),
        "payment_status": payment.get("status") or "pending",
        "payment_qr_code": tx.get("qr_code"),
        "payment_qr_code_base64": tx.get("qr_code_base64"),
        "payment_ticket_url": tx.get("ticket_url"),
    }


def deliver_order(conn, order: Dict[str, Any], admin_id: Optional[int] = None, message: str = "Pagamento aprovado. Plano entregue automaticamente.") -> Dict[str, Any]:
    if order.get("status") == "delivered":
        return {"already_delivered": True, "plan": order.get("plan"), "premium_until": serialize_dt(order.get("premium_until")), "permanent": bool(order.get("permanent"))}
    plan = normalize_plan(order["plan"])
    permanent = bool(order.get("permanent"))
    premium_until = None if permanent else now_utc() + timedelta(minutes=int(order["duration_minutes"]))
    conn.execute(
        update(users)
        .where(users.c.id == order["user_id"])
        .values(plan=plan, premium_until=premium_until, permanent=permanent, updated_at=now_utc())
    )
    conn.execute(
        update(orders)
        .where(orders.c.id == order["id"])
        .values(status="delivered", admin_message=message, approved_at=now_utc(), approved_by=admin_id, delivered_at=now_utc(), payment_paid_at=now_utc())
    )
    add_app_log(conn, order["user_id"], "order_delivered", f"{order['plan_title']} {order['option_name']} entregue. {message}")
    return {"plan": plan, "premium_until": serialize_dt(premium_until), "permanent": permanent}


def sync_mp_payment_for_order(order_id: int) -> Dict[str, Any]:
    with engine.begin() as conn:
        found = conn.execute(select(orders).where(orders.c.id == order_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        order = row_dict(found)
        payment_id = order.get("payment_id")
        if not payment_id:
            return {"order": serialize_order(order), "payment_checked": False, "message": "Pedido sem pagamento Mercado Pago"}
        payment = mp_request("GET", f"/v1/payments/{payment_id}")
        status = payment.get("status") or order.get("payment_status") or "pending"
        values = {"payment_status": status}
        valid_payment, validation_message = mp_payment_matches_order(payment, order, str(order_id))
        if mp_payment_is_approved(status) and valid_payment:
            values["payment_paid_at"] = now_utc()
        conn.execute(update(orders).where(orders.c.id == order_id).values(**values))
        order.update(values)
        delivered = None
        if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
            delivered = deliver_order(conn, order, None, "Pagamento PIX aprovado e validado pelo Mercado Pago. Plano entregue automaticamente.")
        updated = conn.execute(select(orders).where(orders.c.id == order_id)).first()
        return {"order": serialize_order(updated), "payment_checked": True, "mercadopago_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}


def generate_beta_access_key_code() -> str:
    return "BETA-ACCESS-" + secrets.token_hex(5).upper()


def deliver_beta_access_order(conn, order: Dict[str, Any]) -> Dict[str, Any]:
    if order.get("status") == "delivered" and order.get("beta_key_code"):
        return {"already_delivered": True, "beta_key_code": order.get("beta_key_code")}

    key_code = order.get("beta_key_code") or generate_beta_access_key_code()
    expires_at = None
    if not bool(order.get("permanent")):
        days = int(order.get("expires_days") or 1)
        expires_at = now_utc() + timedelta(days=days)

    key_id = order.get("beta_key_id")
    if not key_id:
        try:
            result = conn.execute(
                beta_keys.insert().values(
                    key_hash=hash_text(key_code),
                    display_name=f"Acesso Antecipado Beta - {order.get('duration_label')}",
                    access_level="early_access_beta",
                    max_uses=1,
                    current_uses=0,
                    revoked=False,
                    message="Acesso Antecipado Beta liberado por pagamento PIX.",
                    expires_at=expires_at,
                    created_at=now_utc(),
                )
            )
            key_id = result.inserted_primary_key[0]
        except IntegrityError:
            key_code = generate_beta_access_key_code()
            result = conn.execute(
                beta_keys.insert().values(
                    key_hash=hash_text(key_code),
                    display_name=f"Acesso Antecipado Beta - {order.get('duration_label')}",
                    access_level="early_access_beta",
                    max_uses=1,
                    current_uses=0,
                    revoked=False,
                    message="Acesso Antecipado Beta liberado por pagamento PIX.",
                    expires_at=expires_at,
                    created_at=now_utc(),
                )
            )
            key_id = result.inserted_primary_key[0]

    conn.execute(
        update(beta_access_orders)
        .where(beta_access_orders.c.id == order["id"])
        .values(
            status="delivered",
            payment_paid_at=order.get("payment_paid_at") or now_utc(),
            delivered_at=now_utc(),
            beta_key_code=key_code,
            beta_key_id=key_id,
            message="Pagamento aprovado. Key de Acesso Antecipado Beta entregue automaticamente.",
        )
    )
    add_app_log(conn, None, "beta_access_delivered", f"pedido_beta={order['id']}; {order.get('duration_label')}; {price_label(order.get('price_cents') or 0)}")
    return {"beta_key_code": key_code, "expires_at": serialize_dt(expires_at), "permanent": bool(order.get("permanent"))}


def sync_mp_payment_for_beta_order(order_id: int, order_token: Optional[str] = None) -> Dict[str, Any]:
    with engine.begin() as conn:
        query = select(beta_access_orders).where(beta_access_orders.c.id == order_id)
        if order_token is not None:
            query = query.where(beta_access_orders.c.order_token == str(order_token))
        found = conn.execute(query).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido beta não encontrado")
        order = row_dict(found)
        payment_id = order.get("payment_id")
        if not payment_id:
            return {"order": serialize_beta_access_order(order), "payment_checked": False, "message": "Pedido beta sem pagamento Mercado Pago"}
        payment = mp_request("GET", f"/v1/payments/{payment_id}")
        status = payment.get("status") or order.get("payment_status") or "pending"
        values = {"payment_status": status}
        valid_payment, validation_message = mp_payment_matches_order(payment, order, f"beta:{order_id}")
        if mp_payment_is_approved(status) and valid_payment:
            values["payment_paid_at"] = now_utc()
        conn.execute(update(beta_access_orders).where(beta_access_orders.c.id == order_id).values(**values))
        order.update(values)
        delivered = None
        if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
            delivered = deliver_beta_access_order(conn, order)
        updated = conn.execute(select(beta_access_orders).where(beta_access_orders.c.id == order_id)).first()
        return {"order": serialize_beta_access_order(updated), "payment_checked": True, "mercadopago_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}


# ==================================================
# ROTAS DA LOJA DE TEMAS
# ==================================================


def normalize_theme_id(theme_id: str) -> str:
    value = str(theme_id or "").strip().lower()
    value = re.sub(r"[^a-z0-9_\-]+", "_", value).strip("_")
    if not value or len(value) > 80:
        raise HTTPException(status_code=400, detail="ID do tema inválido")
    return value


def theme_is_auto_weekly_event(theme: Dict[str, Any]) -> bool:
    return str(row_dict(theme).get("id") or "").strip() in WEEKLY_EVENT_THEME_IDS


def weekly_event_window(reference: Optional[datetime] = None) -> Tuple[datetime, datetime, int]:
    ref = reference or now_utc()
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    else:
        ref = ref.astimezone(timezone.utc)
    # Início da semana sempre na segunda-feira 00:00 UTC.
    start = (ref - timedelta(days=ref.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    weeks = max(0, int((start - WEEKLY_EVENT_ANCHOR).days // 7))
    end = start + timedelta(days=7)
    return start, end, weeks


def current_weekly_event_theme_id(reference: Optional[datetime] = None) -> str:
    _, _, weeks = weekly_event_window(reference)
    return WEEKLY_EVENT_THEME_IDS[weeks % len(WEEKLY_EVENT_THEME_IDS)]


def is_current_weekly_event_theme(theme: Dict[str, Any], reference: Optional[datetime] = None) -> bool:
    data = row_dict(theme)
    return theme_is_auto_weekly_event(data) and str(data.get("id")) == current_weekly_event_theme_id(reference)


def theme_access_type(theme: Dict[str, Any]) -> str:
    """Retorna o tipo de ACESSO do usuário após compra.

    Importante: tema de evento semanal vendido na loja continua sendo compra permanente.
    A janela de 7 dias controla apenas se o item aparece na loja, não a posse do comprador.
    """
    raw = str(theme.get("access_type") or "one_time").strip().casefold()
    theme_id = str(theme.get("id") or "").strip()
    if raw in {"subscription", "assinatura", "mensal", "monthly"} or theme_id.endswith("_subscription"):
        return "subscription"
    if raw in {"weekly_free"}:
        return "weekly_event"
    # Evento semanal vendido por PIX é PERMANENTE para quem compra.
    # A rotação semanal controla somente a disponibilidade na aba exclusiva do site.
    if raw in {"event_sale", "weekly_event_sale"} or theme_id in WEEKLY_EVENT_THEME_IDS:
        return "one_time"
    return "one_time"


def theme_is_weekly_event_display(theme: Dict[str, Any]) -> bool:
    data = row_dict(theme)
    theme_id = str(data.get("id") or "").strip()
    category = str(data.get("category") or "").strip().casefold()
    raw = str(data.get("access_type") or "").strip().casefold()
    return theme_id == "diamond_black_event" or theme_id in WEEKLY_EVENT_THEME_IDS or "evento" in category or raw in {"event_sale", "weekly_event_sale"}


def theme_is_listed_for_sale(theme: Dict[str, Any]) -> bool:
    data = row_dict(theme)
    if not bool(data.get("is_active")):
        return False
    # Temas do evento semanal automático NÃO aparecem na loja normal.
    # Eles aparecem apenas no endpoint /themes/weekly-event e na aba exclusiva do site.
    if theme_is_auto_weekly_event(data):
        return False
    if theme_is_weekly_event_display(data):
        starts_at = normalize_dt(data.get("event_starts_at"))
        ends_at = normalize_dt(data.get("event_ends_at"))
        now = now_utc()
        if starts_at and now < starts_at:
            return False
        if ends_at and now >= ends_at:
            return False
    return True


def theme_is_buyable(theme: Dict[str, Any]) -> bool:
    data = row_dict(theme)
    if not bool(data.get("is_active")):
        return False
    if theme_is_auto_weekly_event(data):
        return is_current_weekly_event_theme(data)
    return theme_is_listed_for_sale(data)


def theme_duration_days(theme: Dict[str, Any]) -> Optional[int]:
    access_type = theme_access_type(theme)
    if access_type != "subscription":
        return None
    try:
        days = int(theme.get("duration_days") or 30)
    except Exception:
        days = 30
    return max(1, min(3650, days))


def normalize_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str) and value.strip():
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def entitlement_is_active(entitlement: Optional[Dict[str, Any]]) -> bool:
    if not entitlement:
        return False
    if str(entitlement.get("status") or "active").casefold() not in {"active", "ativo"}:
        return False
    expires_at = normalize_dt(entitlement.get("expires_at"))
    return expires_at is None or expires_at > now_utc()


def subscription_expiry_for(theme: Dict[str, Any], current_expires_at: Any = None) -> Optional[datetime]:
    days = theme_duration_days(theme)
    if days is None:
        return None
    current = normalize_dt(current_expires_at)
    base = current if current and current > now_utc() else now_utc()
    return base + timedelta(days=days)


def serialize_theme(row: Any, owned: bool = False, entitlement: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = row_dict(row)
    entitlement = entitlement or {}
    access_type = theme_access_type(data)
    duration_days = theme_duration_days(data)
    expires_at = normalize_dt(entitlement.get("expires_at"))
    active_owned = bool(owned) and entitlement_is_active(entitlement) if entitlement else bool(owned)
    return {
        "id": data.get("id"),
        "name": data.get("name"),
        "description": data.get("description"),
        "price_cents": int(data.get("price_cents") or 0),
        "price_label": price_label(int(data.get("price_cents") or 0)),
        "preview_url": data.get("preview_url"),
        "accent_color": data.get("accent_color"),
        "category": data.get("category"),
        "access_type": access_type,
        "is_subscription": access_type == "subscription",
        "is_weekly_event": theme_is_weekly_event_display(data),
        "is_temporary": access_type == "subscription",
        "duration_days": duration_days,
        "duration_label": data.get("duration_label") or (f"{duration_days} dias" if duration_days else "Vitalício"),
        "event_starts_at": serialize_dt(data.get("event_starts_at")),
        "event_ends_at": serialize_dt(data.get("event_ends_at")),
        "event_label": data.get("event_label"),
        "store_available": theme_is_listed_for_sale(data),
        "renewable": access_type == "subscription",
        "is_active": bool(data.get("is_active")),
        "owned": active_owned,
        "owned_status": "active" if active_owned else ("expired" if entitlement else "not_owned"),
        "purchased_at": serialize_dt(entitlement.get("purchased_at")) if entitlement else None,
        "expires_at": serialize_dt(expires_at),
        "created_at": serialize_dt(data.get("created_at")),
        "updated_at": serialize_dt(data.get("updated_at")),
    }


def serialize_theme_order(row: Any) -> Dict[str, Any]:
    data = row_dict(row)
    return {
        "id": data.get("id"),
        "user_id": data.get("user_id"),
        "theme_id": data.get("theme_id"),
        "theme_name": data.get("theme_name"),
        "price_cents": int(data.get("price_cents") or 0),
        "price_label": price_label(int(data.get("price_cents") or 0)),
        "access_type": data.get("access_type") or "one_time",
        "duration_days": data.get("duration_days"),
        "access_expires_at": serialize_dt(data.get("access_expires_at")),
        "status": data.get("status"),
        "buyer_name": data.get("buyer_name"),
        "buyer_email": data.get("buyer_email"),
        "receipt_email_sent_at": serialize_dt(data.get("receipt_email_sent_at")),
        "receipt_email_error": data.get("receipt_email_error"),
        "admin_message": data.get("admin_message"),
        "created_at": serialize_dt(data.get("created_at")),
        "delivered_at": serialize_dt(data.get("delivered_at")),
        "cancelled_at": serialize_dt(data.get("cancelled_at")),
        "payment_provider": data.get("payment_provider"),
        "payment_id": data.get("payment_id"),
        "payment_status": data.get("payment_status"),
        "payment_qr_code": data.get("payment_qr_code"),
        "payment_qr_code_base64": data.get("payment_qr_code_base64"),
        "payment_ticket_url": data.get("payment_ticket_url"),
        "payment_created_at": serialize_dt(data.get("payment_created_at")),
        "payment_paid_at": serialize_dt(data.get("payment_paid_at")),
    }


def get_user_theme_entitlement(conn, user_id: int, theme_id: str) -> Optional[Dict[str, Any]]:
    found = conn.execute(
        select(user_themes)
        .where(user_themes.c.user_id == int(user_id), user_themes.c.theme_id == str(theme_id))
        .order_by(user_themes.c.id.desc())
        .limit(1)
    ).first()
    return row_dict(found) if found else None


def user_owns_theme(conn, user_id: int, theme_id: str) -> bool:
    entitlement = get_user_theme_entitlement(conn, user_id, theme_id)
    return entitlement_is_active(entitlement)


def get_theme_or_404(conn, theme_id: str, active_only: bool = False) -> Dict[str, Any]:
    theme_id = normalize_theme_id(theme_id)
    query = select(themes).where(themes.c.id == theme_id)
    if active_only:
        query = query.where(themes.c.is_active == True)  # noqa: E712
    found = conn.execute(query).first()
    if not found:
        raise HTTPException(status_code=404, detail="Tema não encontrado ou indisponível")
    return row_dict(found)


def grant_theme_to_user(conn, user_id: int, theme_id: str, source: str = "purchase", order_id: Optional[int] = None, granted_by: Optional[int] = None, note: Optional[str] = None) -> Dict[str, Any]:
    theme_id = normalize_theme_id(theme_id)
    user_found = conn.execute(select(users.c.id, users.c.username).where(users.c.id == int(user_id))).first()
    if not user_found:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    theme = get_theme_or_404(conn, theme_id, active_only=False)
    access_type = theme_access_type(theme)

    existing = get_user_theme_entitlement(conn, int(user_id), theme_id)
    if existing and access_type != "subscription" and entitlement_is_active(existing):
        if theme_id == "diamond_black_event" and existing.get("expires_at") is not None:
            conn.execute(update(user_themes).where(user_themes.c.id == existing["id"]).values(expires_at=None, status="active"))
            existing = row_dict(conn.execute(select(user_themes).where(user_themes.c.id == existing["id"])).first())
        return {"already_owned": True, "theme": serialize_theme(theme, owned=True, entitlement=existing)}

    expires_at = subscription_expiry_for(theme, existing.get("expires_at") if existing else None)
    if existing:
        conn.execute(
            update(user_themes)
            .where(user_themes.c.id == existing["id"])
            .values(
                source=str(source or "purchase")[:60],
                order_id=order_id,
                granted_by=granted_by,
                note=safe_details(note),
                purchased_at=now_utc(),
                expires_at=expires_at,
                status="active",
            )
        )
        entitlement = row_dict(conn.execute(select(user_themes).where(user_themes.c.id == existing["id"])).first())
        action = "theme_subscription_renewed" if access_type == "subscription" else "theme_reactivated"
    else:
        result = conn.execute(
            user_themes.insert().values(
                user_id=int(user_id),
                theme_id=theme_id,
                source=str(source or "purchase")[:60],
                order_id=order_id,
                granted_by=granted_by,
                note=safe_details(note),
                purchased_at=now_utc(),
                expires_at=expires_at,
                status="active",
            )
        )
        entitlement = row_dict(conn.execute(select(user_themes).where(user_themes.c.id == result.inserted_primary_key[0])).first())
        action = "theme_subscription_started" if access_type == "subscription" else "theme_unlocked"

    add_app_log(conn, int(user_id), action, f"theme={theme_id}; source={source}; order={order_id}; expires_at={serialize_dt(expires_at)}")
    return {"theme": serialize_theme(theme, owned=True, entitlement=entitlement), "expires_at": serialize_dt(expires_at), "access_type": access_type}


def deliver_theme_order(conn, order: Dict[str, Any], message: str = "Pagamento aprovado. Tema entregue automaticamente.") -> Dict[str, Any]:
    if order.get("status") == "delivered":
        return {"already_delivered": True, "theme_id": order.get("theme_id"), "access_expires_at": serialize_dt(order.get("access_expires_at"))}

    granted = grant_theme_to_user(
        conn,
        int(order["user_id"]),
        str(order["theme_id"]),
        source="subscription" if str(order.get("access_type") or "") == "subscription" else ("weekly_event" if str(order.get("access_type") or "") == "weekly_event" else "purchase"),
        order_id=int(order["id"]),
        note=message,
    )
    expires_at = granted.get("expires_at")
    expires_dt = normalize_dt(expires_at)
    delivered_at = now_utc()
    paid_at = order.get("payment_paid_at") or delivered_at
    conn.execute(
        update(theme_orders)
        .where(theme_orders.c.id == int(order["id"]))
        .values(
            status="delivered",
            admin_message=message,
            delivered_at=delivered_at,
            access_expires_at=expires_dt,
            payment_paid_at=paid_at,
        )
    )
    email_order = dict(order)
    email_order.update({
        "status": "delivered",
        "admin_message": message,
        "delivered_at": delivered_at,
        "access_expires_at": expires_dt,
        "payment_paid_at": paid_at,
    })
    receipt_email = send_theme_receipt_email(conn, email_order)
    if granted.get("access_type") == "subscription":
        log_msg = f"assinatura_30d theme={order['theme_id']}; pedido_tema={order['id']}; expira={expires_at}; {message}"
    elif str(order.get("theme_id")) == "diamond_black_event" or str(order.get("theme_id")) in WEEKLY_EVENT_THEME_IDS:
        log_msg = f"evento_semanal_permanente theme={order['theme_id']}; pedido_tema={order['id']}; acesso_permanente; {message}"
    elif granted.get("access_type") == "weekly_event":
        log_msg = f"tema_semanal_temporario theme={order['theme_id']}; pedido_tema={order['id']}; expira={expires_at}; {message}"
    else:
        log_msg = f"theme={order['theme_id']}; pedido_tema={order['id']}; {message}"
    add_app_log(conn, int(order["user_id"]), "theme_order_delivered", log_msg)
    return {"theme_id": order.get("theme_id"), "theme": granted.get("theme"), "access_expires_at": expires_at, "access_type": granted.get("access_type"), "receipt_email": receipt_email}


def sync_mp_payment_for_theme_order(order_id: int) -> Dict[str, Any]:
    with engine.begin() as conn:
        found = conn.execute(select(theme_orders).where(theme_orders.c.id == int(order_id))).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido de tema não encontrado")
        order = row_dict(found)
        payment_id = order.get("payment_id")
        if not payment_id:
            return {"order": serialize_theme_order(order), "payment_checked": False, "message": "Pedido de tema sem pagamento Mercado Pago"}
        payment = mp_request("GET", f"/v1/payments/{payment_id}")
        status = payment.get("status") or order.get("payment_status") or "pending"
        values = {"payment_status": status}
        valid_payment, validation_message = mp_payment_matches_order(payment, order, f"theme:{order_id}")
        if mp_payment_is_approved(status) and valid_payment:
            values["payment_paid_at"] = now_utc()
        conn.execute(update(theme_orders).where(theme_orders.c.id == int(order_id)).values(**values))
        order.update(values)
        delivered = None
        if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
            delivered = deliver_theme_order(conn, order, "Pagamento PIX aprovado e validado pelo Mercado Pago. Tema entregue automaticamente.")
        updated = conn.execute(select(theme_orders).where(theme_orders.c.id == int(order_id))).first()
        return {"order": serialize_theme_order(updated), "payment_checked": True, "mercadopago_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}


@app.get("/themes/store")
def list_theme_store():
    with engine.connect() as conn:
        rows = conn.execute(
            select(themes).where(themes.c.is_active == True).order_by(themes.c.category.asc(), themes.c.name.asc())  # noqa: E712
        ).fetchall()
    visible = [row for row in rows if theme_is_listed_for_sale(row_dict(row))]
    return {"themes": [serialize_theme(row) for row in visible]}


@app.get("/themes/weekly-event")
def current_weekly_event_theme(user: Optional[Dict[str, Any]] = Depends(get_optional_user_by_token)):
    start, end, weeks = weekly_event_window()
    active_id = current_weekly_event_theme_id()
    with engine.connect() as conn:
        row = conn.execute(select(themes).where(themes.c.id == active_id, themes.c.is_active == True)).first()  # noqa: E712
        if not row:
            raise HTTPException(status_code=404, detail="Tema semanal não configurado")
        entitlement = None
        owned = False
        if user:
            entitlement = get_user_theme_entitlement(conn, int(user["id"]), active_id)
            owned = bool(entitlement and entitlement_is_active(entitlement))
    theme = serialize_theme(row, owned=owned, entitlement=entitlement)
    theme.update({
        "is_weekly_event": True,
        "weekly_event": True,
        "event_starts_at": serialize_dt(start),
        "event_ends_at": serialize_dt(end),
        "next_rotation_at": serialize_dt(end),
        "rotation_label": "Troca automática toda segunda-feira",
        "event_label": "Disponível somente esta semana na aba Evento Semanal. Quem comprar fica com acesso permanente.",
        "week_index": weeks,
        "pool_count": len(WEEKLY_EVENT_THEME_IDS),
        "hidden_from_main_store": True,
    })
    return {"theme": theme, "week_start": serialize_dt(start), "week_end": serialize_dt(end), "next_rotation_at": serialize_dt(end), "pool_count": len(WEEKLY_EVENT_THEME_IDS)}


@app.get("/themes/my")
def my_themes(user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        entitlement_rows = conn.execute(
            select(user_themes).where(user_themes.c.user_id == int(user["id"])).order_by(user_themes.c.id.desc())
        ).fetchall()
        entitlements: Dict[str, Dict[str, Any]] = {}
        expired_entitlements: Dict[str, Dict[str, Any]] = {}
        for row in entitlement_rows:
            data = row_dict(row)
            theme_id = str(data.get("theme_id"))
            if theme_id in entitlements:
                continue
            if entitlement_is_active(data):
                entitlements[theme_id] = data
            elif theme_id not in expired_entitlements:
                expired_entitlements[theme_id] = data
        owned_ids = set(entitlements)
        store_rows_raw = conn.execute(
            select(themes).where(themes.c.is_active == True).order_by(themes.c.category.asc(), themes.c.name.asc())  # noqa: E712
        ).fetchall()
        visible_rows = [row for row in store_rows_raw if theme_is_listed_for_sale(row_dict(row))]
        needed_ids = set(entitlements) | set(expired_entitlements)
        extra_rows = []
        if needed_ids:
            extra_rows = conn.execute(select(themes).where(themes.c.id.in_(list(needed_ids)))).fetchall()
    row_by_id: Dict[str, Any] = {}
    for row in [*visible_rows, *extra_rows]:
        row_by_id[str(row_dict(row).get("id"))] = row
    all_themes = []
    expired = []
    for theme_id, row in row_by_id.items():
        entitlement = entitlements.get(theme_id)
        expired_entitlement = expired_entitlements.get(theme_id)
        all_themes.append(serialize_theme(row, owned=theme_id in owned_ids, entitlement=entitlement or expired_entitlement))
        if expired_entitlement and theme_id not in owned_ids:
            expired.append(serialize_theme(row, owned=False, entitlement=expired_entitlement))
    return {
        "themes": [theme for theme in all_themes if theme["owned"]],
        "expired_themes": expired,
        "owned_theme_ids": sorted(owned_ids),
        "store": all_themes,
    }


@app.post("/themes/purchase")
def purchase_theme(data: ThemePurchaseRequest, user: Dict[str, Any] = Depends(get_user_by_token)):
    theme_id = normalize_theme_id(data.theme_id)
    with engine.begin() as conn:
        theme = get_theme_or_404(conn, theme_id, active_only=True)
        existing_entitlement = get_user_theme_entitlement(conn, int(user["id"]), theme_id)
        access_type = theme_access_type(theme)
        if existing_entitlement and access_type != "subscription" and entitlement_is_active(existing_entitlement):
            return {"message": "Tema já liberado na sua conta", "owned": True, "theme": serialize_theme(theme, owned=True, entitlement=existing_entitlement)}
        if not theme_is_buyable(theme):
            raise HTTPException(status_code=400, detail="Este tema de evento semanal não está disponível para compra nesta semana. Quem já comprou continua com acesso permanente.")

        recent_orders = int(conn.execute(
            select(func.count()).select_from(theme_orders).where(
                theme_orders.c.user_id == int(user["id"]),
                theme_orders.c.created_at >= now_utc() - timedelta(minutes=10),
            )
        ).scalar_one() or 0)
        open_orders = int(conn.execute(
            select(func.count()).select_from(theme_orders).where(
                theme_orders.c.user_id == int(user["id"]),
                theme_orders.c.status.in_(["pending", "payment_pending"]),
            )
        ).scalar_one() or 0)
        if recent_orders >= 5 or open_orders >= 8:
            add_security_event(conn, "theme_order_spam_blocked", False, user_id=user["id"], username=user.get("username"), details=f"recent={recent_orders}; open={open_orders}")
            raise HTTPException(status_code=429, detail="Muitos pedidos de tema em pouco tempo. Aguarde ou finalize pedidos antigos.")

        result = conn.execute(
            theme_orders.insert().values(
                user_id=int(user["id"]),
                theme_id=theme_id,
                theme_name=theme["name"],
                price_cents=int(theme.get("price_cents") or 0),
                access_type=access_type,
                duration_days=theme_duration_days(theme),
                status="pending",
                buyer_name=str(data.buyer_name or user.get("username") or "Cliente")[:120],
                buyer_email=str(data.buyer_email or "")[:180] or None,
                payment_provider="mercadopago" if mercadopago_enabled() and int(theme.get("price_cents") or 0) > 0 else "manual",
                payment_status="pending" if mercadopago_enabled() and int(theme.get("price_cents") or 0) > 0 else None,
                created_at=now_utc(),
            )
        )
        order_id = result.inserted_primary_key[0]
        log_kind = "assinatura" if access_type == "subscription" else ("evento_semanal_permanente" if theme_is_weekly_event_display(theme) else "compra")
        add_app_log(conn, user["id"], "theme_order_created", f"pedido_tema={order_id}; theme={theme_id}; tipo={log_kind}; price={price_label(theme.get('price_cents') or 0)}")

        if int(theme.get("price_cents") or 0) <= 0:
            order = row_dict(conn.execute(select(theme_orders).where(theme_orders.c.id == order_id)).first())
            delivered = deliver_theme_order(conn, order, "Tema gratuito liberado automaticamente.")
            updated = conn.execute(select(theme_orders).where(theme_orders.c.id == order_id)).first()
            return {"message": "Tema gratuito liberado", "order_id": order_id, "status": "delivered", "order": serialize_theme_order(updated), "delivered": delivered}

    payment_payload = {}
    message = "Pedido de tema enviado para análise do admin"
    status = "pending"
    if mercadopago_enabled():
        payer_email = str(data.buyer_email or "").strip()
        if not payer_email:
            payer_email = make_mp_payer_email(user)
        else:
            payer_email = valid_email_or_technical(payer_email, str(data.buyer_name or user.get("username") or "cliente"))
        payment_payload = create_mp_pix_payment_public(
            external_reference=f"theme:{order_id}",
            amount_cents=int(theme["price_cents"]),
            description=f"PC Ultra Manager - Tema {theme['name']}",
            payer_email=payer_email,
            payer_name=str(data.buyer_name or user.get("username") or "Cliente"),
            idempotency_prefix=f"theme-{order_id}",
        )
        with engine.begin() as conn:
            conn.execute(
                update(theme_orders)
                .where(theme_orders.c.id == int(order_id))
                .values(
                    status="payment_pending",
                    payment_provider="mercadopago",
                    payment_id=payment_payload.get("payment_id"),
                    payment_status=payment_payload.get("payment_status"),
                    payment_qr_code=payment_payload.get("payment_qr_code"),
                    payment_qr_code_base64=payment_payload.get("payment_qr_code_base64"),
                    payment_ticket_url=payment_payload.get("payment_ticket_url"),
                    payment_created_at=now_utc(),
                )
            )
        if access_type == "subscription":
            message = "Assinatura criada. Pague o PIX para liberar 30 dias de Matrix no app."
        elif theme_is_weekly_event_display(theme):
            message = "Pedido de evento semanal criado. Pague o PIX para liberar o tema permanentemente na sua conta."
        else:
            message = "Pedido de tema criado. Pague o PIX para liberar no app."
        status = "payment_pending"

    return {
        "message": message,
        "order_id": order_id,
        "status": status,
        "theme": serialize_theme(theme, owned=False, entitlement=existing_entitlement if 'existing_entitlement' in locals() else None),
        "access_type": access_type,
        "duration_days": theme_duration_days(theme),
        "duration_label": theme.get("duration_label") or ("30 dias" if access_type == "subscription" else "Vitalício"),
        "is_weekly_event": theme_is_weekly_event_display(theme),
        "event_ends_at": serialize_dt(theme.get("event_ends_at")),
        "event_label": theme.get("event_label"),
        **payment_payload,
    }


@app.get("/themes/orders/{order_id}/payment-status")
def theme_order_payment_status(order_id: int, user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        found = conn.execute(select(theme_orders).where(theme_orders.c.id == int(order_id))).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido de tema não encontrado")
        order = row_dict(found)
        if int(order.get("user_id")) != int(user.get("id")) and not is_admin(user):
            raise HTTPException(status_code=403, detail="Acesso negado")
    if order.get("payment_provider") == "mercadopago" and order.get("payment_id") and order.get("status") != "delivered":
        return sync_mp_payment_for_theme_order(order_id)
    return {"order": serialize_theme_order(order), "payment_checked": False}


@app.get("/admin/themes")
def admin_list_themes(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(themes).order_by(themes.c.category.asc(), themes.c.name.asc())).fetchall()
    return {"themes": [serialize_theme(row) for row in rows]}


@app.post("/admin/themes/create")
def admin_create_theme(data: ThemeCreateRequest, admin: Dict[str, Any] = Depends(require_admin)):
    theme_id = normalize_theme_id(data.id)
    values = {
        "id": theme_id,
        "name": data.name.strip(),
        "description": safe_details(data.description),
        "price_cents": int(data.price_cents),
        "preview_url": str(data.preview_url or "").strip() or None,
        "accent_color": str(data.accent_color or "").strip() or None,
        "category": str(data.category or "premium").strip()[:80] or "premium",
        "access_type": "subscription" if str(data.access_type or "one_time").strip().casefold() in {"subscription", "assinatura", "mensal"} else "one_time",
        "duration_days": int(data.duration_days or 30) if str(data.access_type or "one_time").strip().casefold() in {"subscription", "assinatura", "mensal"} else None,
        "duration_label": data.duration_label or ("30 dias" if str(data.access_type or "one_time").strip().casefold() in {"subscription", "assinatura", "mensal"} else "Vitalício"),
        "is_active": bool(data.is_active),
        "created_by": int(admin["id"]),
        "updated_at": now_utc(),
    }
    with engine.begin() as conn:
        existing = conn.execute(select(themes.c.id).where(themes.c.id == theme_id)).first()
        if existing:
            update_values = dict(values)
            update_values.pop("id", None)
            update_values.pop("created_by", None)
            conn.execute(update(themes).where(themes.c.id == theme_id).values(**update_values))
            action = "theme_updated"
        else:
            values["created_at"] = now_utc()
            conn.execute(themes.insert().values(**values))
            action = "theme_created"
        add_admin_log(conn, admin["id"], action, theme_id, f"price={price_label(data.price_cents)}; active={data.is_active}")
        found = conn.execute(select(themes).where(themes.c.id == theme_id)).first()
    return {"message": "Tema salvo", "theme": serialize_theme(found)}


@app.post("/admin/themes/give")
def admin_give_theme(data: ThemeGiveRequest, admin: Dict[str, Any] = Depends(require_admin)):
    theme_id = normalize_theme_id(data.theme_id)
    with engine.begin() as conn:
        granted = grant_theme_to_user(conn, int(data.user_id), theme_id, source="admin", granted_by=int(admin["id"]), note=data.message or "Tema liberado pelo admin")
        add_admin_log(conn, admin["id"], "theme_given", f"user={data.user_id}; theme={theme_id}", data.message or "Tema liberado pelo admin")
    return {"message": "Tema liberado para o usuário", **granted}


@app.post("/admin/themes/remove")
@app.delete("/admin/themes/remove")
def admin_remove_theme(data: ThemeRemoveRequest, admin: Dict[str, Any] = Depends(require_admin)):
    theme_id = normalize_theme_id(data.theme_id)
    with engine.begin() as conn:
        result = conn.execute(user_themes.delete().where(user_themes.c.user_id == int(data.user_id), user_themes.c.theme_id == theme_id))
        add_admin_log(conn, admin["id"], "theme_removed", f"user={data.user_id}; theme={theme_id}", f"removed={result.rowcount}")
        add_app_log(conn, int(data.user_id), "theme_removed_by_admin", f"theme={theme_id}")
    return {"message": "Tema removido do usuário", "removed": int(result.rowcount or 0)}


@app.get("/admin/theme-orders")
def admin_theme_orders(status: str = Query("todos"), admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        query = select(theme_orders).order_by(theme_orders.c.id.desc()).limit(300)
        if status and status != "todos":
            query = query.where(theme_orders.c.status == status)
        rows = conn.execute(query).fetchall()
    return {"orders": [serialize_theme_order(row) for row in rows]}


@app.post("/admin/theme-orders/approve")
def admin_approve_theme_order(data: ThemeOrderActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    message = data.message or "Pedido de tema aprovado manualmente pelo admin."
    with engine.begin() as conn:
        found = conn.execute(select(theme_orders).where(theme_orders.c.id == int(data.order_id))).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido de tema não encontrado")
        order = row_dict(found)
        if order.get("status") == "cancelled":
            raise HTTPException(status_code=400, detail="Pedido cancelado não pode ser aprovado")
        delivered = deliver_theme_order(conn, order, message)
        add_admin_log(conn, admin["id"], "theme_order_approved", str(data.order_id), message)
        updated = conn.execute(select(theme_orders).where(theme_orders.c.id == int(data.order_id))).first()
    return {"message": "Pedido de tema aprovado", "order": serialize_theme_order(updated), "delivered": delivered}


@app.post("/admin/theme-orders/cancel")
def admin_cancel_theme_order(data: ThemeOrderActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    message = data.message or "Pedido de tema cancelado pelo admin."
    with engine.begin() as conn:
        found = conn.execute(select(theme_orders).where(theme_orders.c.id == int(data.order_id))).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido de tema não encontrado")
        order = row_dict(found)
        if order.get("status") == "delivered":
            raise HTTPException(status_code=400, detail="Pedido já entregue não pode ser cancelado")
        conn.execute(
            update(theme_orders)
            .where(theme_orders.c.id == int(data.order_id))
            .values(status="cancelled", cancelled_at=now_utc(), admin_message=message)
        )
        add_admin_log(conn, admin["id"], "theme_order_cancelled", str(data.order_id), message)
        updated = conn.execute(select(theme_orders).where(theme_orders.c.id == int(data.order_id))).first()
    return {"message": "Pedido de tema cancelado", "order": serialize_theme_order(updated)}


@app.post("/orders/create")
def create_order(data: CreateOrderRequest, user: Dict[str, Any] = Depends(get_user_by_token)):
    plan = normalize_plan(data.plan)
    option = find_catalog_option(plan, data.option_name, data.duration_minutes, data.permanent, data.price_cents)
    if plan == "free" or int(option["price_cents"]) <= 0:
        raise HTTPException(status_code=400, detail="Plano Free não precisa de pedido")

    with engine.begin() as conn:
        recent_orders = int(conn.execute(
            select(func.count()).select_from(orders).where(
                orders.c.user_id == user["id"],
                orders.c.created_at >= now_utc() - timedelta(minutes=10),
            )
        ).scalar_one() or 0)
        open_orders = int(conn.execute(
            select(func.count()).select_from(orders).where(
                orders.c.user_id == user["id"],
                orders.c.status.in_(["pending", "payment_pending"]),
            )
        ).scalar_one() or 0)
        if recent_orders >= 3 or open_orders >= 5:
            add_security_event(conn, "order_spam_blocked", False, user_id=user["id"], username=user.get("username"), details=f"recent={recent_orders}; open={open_orders}")
            raise HTTPException(status_code=429, detail="Muitos pedidos em pouco tempo. Aguarde ou finalize/cancele pedidos antigos.")

        result = conn.execute(
            orders.insert().values(
                user_id=user["id"],
                plan=plan,
                plan_title=public_plan_name(plan),
                option_name=option["option_name"],
                duration_label=option["duration_label"],
                duration_minutes=option.get("duration_minutes"),
                permanent=bool(option.get("permanent")),
                price_cents=int(option["price_cents"]),
                status="pending",
                payment_provider="mercadopago" if mercadopago_enabled() else "manual",
                payment_status="pending" if mercadopago_enabled() else None,
                user_message=safe_details(data.user_message),
                created_at=now_utc(),
            )
        )
        order_id = result.inserted_primary_key[0]
        add_app_log(conn, user["id"], "order_created", f"pedido={order_id}; plan={plan}; option={option['option_name']}; price={price_label(option['price_cents'])}")

    payment_payload = {}
    message = "Pedido enviado para análise do admin"
    status = "pending"
    if mercadopago_enabled():
        payment_payload = create_mp_pix_payment(order_id, user, option, plan)
        with engine.begin() as conn:
            conn.execute(
                update(orders)
                .where(orders.c.id == order_id)
                .values(
                    status="payment_pending",
                    payment_provider="mercadopago",
                    payment_id=payment_payload.get("payment_id"),
                    payment_status=payment_payload.get("payment_status"),
                    payment_qr_code=payment_payload.get("payment_qr_code"),
                    payment_qr_code_base64=payment_payload.get("payment_qr_code_base64"),
                    payment_ticket_url=payment_payload.get("payment_ticket_url"),
                    payment_created_at=now_utc(),
                )
            )
        message = "Pedido criado. Pague o PIX para liberação automática."
        status = "payment_pending"

    return {
        "message": message,
        "order_id": order_id,
        "status": status,
        "plan": plan,
        "plan_title": public_plan_name(plan),
        "option_name": option["option_name"],
        "duration_label": option["duration_label"],
        "duration_minutes": option.get("duration_minutes"),
        "permanent": bool(option.get("permanent")),
        "price_cents": option["price_cents"],
        "price_label": price_label(option["price_cents"]),
        **payment_payload,
    }


@app.get("/orders/my")
def my_orders(user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        rows = conn.execute(
            select(orders).where(orders.c.user_id == user["id"]).order_by(orders.c.id.desc()).limit(100)
        ).fetchall()
    return {"orders": [serialize_order(row) for row in rows]}



@app.get("/orders/{order_id}/payment-status")
def order_payment_status(order_id: int, user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.connect() as conn:
        found = conn.execute(select(orders).where(orders.c.id == order_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        order = row_dict(found)
        if order.get("user_id") != user.get("id") and not is_admin(user):
            raise HTTPException(status_code=403, detail="Acesso negado")
    if order.get("payment_provider") == "mercadopago" and order.get("payment_id") and order.get("status") != "delivered":
        return sync_mp_payment_for_order(order_id)
    return {"order": serialize_order(order), "payment_checked": False}


@app.post("/payments/mercadopago/webhook")
async def mercadopago_webhook(request: Request):
    # Segurança: o payload não libera plano sozinho. O servidor valida assinatura
    # quando houver secret, consulta o pagamento na API do Mercado Pago e confere
    # external_reference, payment_id, método PIX e valor antes de entregar.
    try:
        body = await request.json()
    except Exception:
        body = {}

    payment_id = None
    if isinstance(body, dict):
        payment_id = (body.get("data") or {}).get("id") or body.get("id")
    payment_id = payment_id or request.query_params.get("data.id") or request.query_params.get("id")
    event_type = request.query_params.get("type") or (body.get("type") if isinstance(body, dict) else None)

    if not payment_id:
        return {"ok": True, "ignored": True, "reason": "sem payment id"}

    if not verify_mp_webhook_signature(request, str(payment_id)):
        raise HTTPException(status_code=401, detail="Assinatura Mercado Pago inválida")

    payment = mp_request("GET", f"/v1/payments/{payment_id}")
    external_reference = payment.get("external_reference")
    status = payment.get("status") or "pending"
    if not external_reference:
        return {"ok": True, "ignored": True, "reason": "sem external_reference", "payment_status": status}

    external_reference = str(external_reference)
    if external_reference.startswith("theme:"):
        try:
            theme_order_id = int(external_reference.split(":", 1)[1])
        except Exception:
            return {"ok": True, "ignored": True, "reason": "external_reference theme inválida", "payment_status": status}
        with engine.begin() as conn:
            found = conn.execute(select(theme_orders).where(theme_orders.c.id == theme_order_id)).first()
            if not found:
                return {"ok": True, "ignored": True, "reason": "pedido de tema não encontrado", "payment_status": status}
            order = row_dict(found)
            valid_payment, validation_message = mp_payment_matches_order(payment, order, f"theme:{theme_order_id}")
            values = {"payment_status": status}
            if mp_payment_is_approved(status) and valid_payment:
                values["payment_paid_at"] = now_utc()
            conn.execute(update(theme_orders).where(theme_orders.c.id == theme_order_id).values(**values))
            delivered = None
            if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
                order["payment_status"] = status
                order["payment_paid_at"] = now_utc()
                delivered = deliver_theme_order(conn, order, "Pagamento PIX aprovado e validado pelo Mercado Pago. Tema entregue automaticamente.")
            add_app_log(conn, order.get("user_id"), "mercadopago_theme_webhook", f"payment={payment_id}; status={status}; event={event_type}; theme_order={theme_order_id}; valid={valid_payment}; {validation_message}")
        return {"ok": True, "theme_order_id": theme_order_id, "payment_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}

    if external_reference.startswith("beta:"):
        try:
            beta_order_id = int(external_reference.split(":", 1)[1])
        except Exception:
            return {"ok": True, "ignored": True, "reason": "external_reference beta inválida", "payment_status": status}
        with engine.begin() as conn:
            found = conn.execute(select(beta_access_orders).where(beta_access_orders.c.id == beta_order_id)).first()
            if not found:
                return {"ok": True, "ignored": True, "reason": "pedido beta não encontrado", "payment_status": status}
            order = row_dict(found)
            valid_payment, validation_message = mp_payment_matches_order(payment, order, f"beta:{beta_order_id}")
            values = {"payment_status": status}
            if mp_payment_is_approved(status) and valid_payment:
                values["payment_paid_at"] = now_utc()
            conn.execute(update(beta_access_orders).where(beta_access_orders.c.id == beta_order_id).values(**values))
            delivered = None
            if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
                order["payment_status"] = status
                order["payment_paid_at"] = now_utc()
                delivered = deliver_beta_access_order(conn, order)
            add_app_log(conn, None, "mercadopago_beta_webhook", f"payment={payment_id}; status={status}; event={event_type}; beta_order={beta_order_id}; valid={valid_payment}; {validation_message}")
        return {"ok": True, "beta_order_id": beta_order_id, "payment_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}

    try:
        order_id = int(external_reference)
    except Exception:
        return {"ok": True, "ignored": True, "reason": "external_reference inválida", "payment_status": status}
    with engine.begin() as conn:
        found = conn.execute(select(orders).where(orders.c.id == order_id)).first()
        if not found:
            return {"ok": True, "ignored": True, "reason": "pedido não encontrado", "payment_status": status}
        order = row_dict(found)
        valid_payment, validation_message = mp_payment_matches_order(payment, order, str(order_id))
        values = {"payment_status": status}
        if mp_payment_is_approved(status) and valid_payment:
            values["payment_paid_at"] = now_utc()
        conn.execute(update(orders).where(orders.c.id == order_id).values(**values))
        delivered = None
        if mp_payment_is_approved(status) and valid_payment and order.get("status") != "delivered":
            order["payment_status"] = status
            delivered = deliver_order(conn, order, None, "Pagamento PIX aprovado e validado pelo Mercado Pago. Plano entregue automaticamente.")
        add_app_log(conn, order.get("user_id"), "mercadopago_webhook", f"payment={payment_id}; status={status}; event={event_type}; valid={valid_payment}; {validation_message}")
    return {"ok": True, "order_id": order_id, "payment_status": status, "payment_validated": valid_payment, "validation_message": validation_message, "delivered": delivered}


@app.get("/admin/beta-access-orders")
def admin_beta_access_orders(status: str = Query("todos"), admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        query = select(beta_access_orders).order_by(beta_access_orders.c.id.desc()).limit(300)
        if status and status != "todos":
            query = query.where(beta_access_orders.c.status == status)
        rows = conn.execute(query).fetchall()
    return {"orders": [serialize_beta_access_order(row) for row in rows]}


@app.get("/admin/orders")
def admin_list_orders(status: str = Query("todos"), admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        query = (
            select(orders, users.c.username.label("username"))
            .select_from(orders.join(users, users.c.id == orders.c.user_id))
            .order_by(orders.c.id.desc())
        )
        if status and status != "todos":
            query = query.where(orders.c.status == status)
        rows = conn.execute(query.limit(300)).fetchall()
    payload = []
    for row in rows:
        data = serialize_order(row)
        mapped = row_dict(row)
        data["username"] = mapped.get("username")
        payload.append(data)
    return {"orders": payload}


@app.post("/admin/orders/approve")
def admin_approve_order(data: OrderActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    message = str(data.message or "Pedido aprovado pelo administrador.").strip()[:1000]
    with engine.begin() as conn:
        found = conn.execute(select(orders).where(orders.c.id == data.order_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        order = row_dict(found)
        if order.get("status") not in {"pending", "payment_pending", "approved"}:
            raise HTTPException(status_code=400, detail="Pedido não está pendente")
        target = conn.execute(select(users).where(users.c.id == order["user_id"])).first()
        if not target:
            raise HTTPException(status_code=404, detail="Usuário do pedido não encontrado")
        plan = normalize_plan(order["plan"])
        permanent = bool(order.get("permanent"))
        premium_until = None if permanent else now_utc() + timedelta(minutes=int(order["duration_minutes"]))
        conn.execute(
            update(users)
            .where(users.c.id == order["user_id"])
            .values(plan=plan, premium_until=premium_until, permanent=permanent, updated_at=now_utc())
        )
        conn.execute(
            update(orders)
            .where(orders.c.id == data.order_id)
            .values(
                status="delivered",
                admin_message=message,
                approved_at=now_utc(),
                approved_by=admin["id"],
                delivered_at=now_utc(),
            )
        )
        add_admin_log(conn, admin["id"], "order_approved", str(data.order_id), f"user={order['user_id']}; plan={plan}; message={message}")
        add_app_log(conn, order["user_id"], "order_delivered", f"{order['plan_title']} {order['option_name']} aprovado. {message}")
    return {"message": "Pedido aprovado e plano entregue", "order_id": data.order_id, "plan": plan, "premium_until": serialize_dt(premium_until), "permanent": permanent}


@app.post("/admin/orders/cancel")
def admin_cancel_order(data: OrderActionRequest, admin: Dict[str, Any] = Depends(require_admin)):
    message = str(data.message or "Pedido cancelado pelo administrador.").strip()[:1000]
    with engine.begin() as conn:
        found = conn.execute(select(orders).where(orders.c.id == data.order_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")
        order = row_dict(found)
        if order.get("status") == "delivered":
            raise HTTPException(status_code=400, detail="Pedido já entregue não pode ser cancelado")
        conn.execute(
            update(orders)
            .where(orders.c.id == data.order_id)
            .values(status="cancelled", admin_message=message, cancelled_at=now_utc())
        )
        add_admin_log(conn, admin["id"], "order_cancelled", str(data.order_id), message)
        add_app_log(conn, order["user_id"], "order_cancelled", message)
    return {"message": "Pedido cancelado", "order_id": data.order_id}


# ==================================================
# ROTAS ADMIN
# ==================================================

@app.post("/admin/keys/create")
async def create_key(
    request: Request,
    display_name: Optional[str] = Query(None),
    key_code: Optional[str] = Query(None),
    plan: str = Query("premium"),
    duration_minutes: Optional[int] = Query(30),
    admin: Dict[str, Any] = Depends(require_admin),
):
    # Compatível com o app atual, que envia params, e com chamadas JSON futuras.
    try:
        body = await request.json()
        if isinstance(body, dict):
            display_name = body.get("display_name", display_name)
            key_code = body.get("key_code", key_code)
            plan = body.get("plan", plan)
            duration_minutes = body.get("duration_minutes", duration_minutes)
    except Exception:
        pass

    display_name = str(display_name or "").strip()
    key_code = str(key_code or "").strip()
    plan = normalize_plan(plan)

    if plan == "free":
        raise HTTPException(status_code=400, detail="Não crie key para plano Free")
    if not display_name:
        raise HTTPException(status_code=400, detail="Nome da key ausente")
    if not key_code:
        raise HTTPException(status_code=400, detail="Código da key ausente")

    permanent = duration_minutes in (None, 0, -1)
    if not permanent and int(duration_minutes) <= 0:
        raise HTTPException(status_code=400, detail="Duração inválida")

    with engine.begin() as conn:
        try:
            conn.execute(
                license_keys.insert().values(
                    key_code_hash=hash_text(key_code),
                    display_name=display_name,
                    plan=plan,
                    duration_minutes=None if permanent else int(duration_minutes),
                    permanent=permanent,
                    created_by=admin["id"],
                    created_at=now_utc(),
                )
            )
        except IntegrityError:
            raise HTTPException(status_code=400, detail="Key já existe")
        add_admin_log(conn, admin["id"], "key_created", display_name, f"plan={plan}; permanent={permanent}")

    return {
        "message": "Key criada com sucesso",
        "display_name": display_name,
        "key_code": key_code,
        "plan": plan,
        "plan_name": public_plan_name(plan),
        "duration_minutes": None if permanent else int(duration_minutes),
        "permanent": permanent,
    }


@app.get("/admin/keys")
def list_keys(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(license_keys).order_by(license_keys.c.id.desc())).fetchall()

    return {
        "keys": [
            {
                "id": row_dict(row)["id"],
                "display_name": row_dict(row)["display_name"],
                "plan": row_dict(row)["plan"],
                "plan_name": public_plan_name(row_dict(row)["plan"]),
                "duration_minutes": row_dict(row).get("duration_minutes"),
                "permanent": bool(row_dict(row).get("permanent")),
                "is_used": bool(row_dict(row).get("is_used")),
                "revoked": bool(row_dict(row).get("revoked")),
                "used_by": row_dict(row).get("used_by"),
                "used_at": serialize_dt(row_dict(row).get("used_at")),
                "created_by": row_dict(row).get("created_by"),
                "created_at": serialize_dt(row_dict(row).get("created_at")),
            }
            for row in rows
        ]
    }


@app.post("/admin/keys/revoke")
def revoke_key(data: RevokeKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if data.key_id is None and not data.key_code:
        raise HTTPException(status_code=400, detail="Informe key_id ou key_code")

    with engine.begin() as conn:
        condition = license_keys.c.id == data.key_id if data.key_id is not None else license_keys.c.key_code_hash == hash_text(data.key_code.strip())
        found = conn.execute(select(license_keys).where(condition)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Key não encontrada")
        key = row_dict(found)
        conn.execute(update(license_keys).where(license_keys.c.id == key["id"]).values(revoked=True))
        add_admin_log(conn, admin["id"], "key_revoked", key["display_name"], f"id={key['id']}")

    return {"message": "Key revogada com sucesso", "key_id": key["id"], "display_name": key["display_name"]}


@app.get("/admin/users")
def list_users(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(users).order_by(users.c.id.desc())).fetchall()

    payload = []
    for row in rows:
        user = row_dict(row)
        lic = user_license_payload(user)
        payload.append(
            {
                "id": user["id"],
                "username": user["username"],
                "role": user.get("role", "user"),
                "plan": lic["plan"],
                "plan_name": lic["plan_name"],
                "premium_active": lic["premium_active"],
                "premium_until": lic["premium_until"],
                "permanent": lic["permanent"],
                "disabled": bool(user.get("disabled")),
                "ban_level": user.get("ban_level"),
                "ban_message": user.get("ban_message"),
                "banned_until": serialize_dt(user.get("banned_until")),
                "created_at": serialize_dt(user.get("created_at")),
            }
        )

    return {"users": payload}


@app.post("/admin/users/change-plan")
def change_user_plan(data: ChangePlanRequest, admin: Dict[str, Any] = Depends(require_admin)):
    plan = normalize_plan(data.plan)
    permanent = bool(data.permanent) if data.permanent is not None else False
    premium_until = None

    if plan == "free":
        permanent = False
    elif plan == "admin":
        permanent = True
    elif data.premium_until:
        premium_until = datetime.fromisoformat(data.premium_until.replace("Z", "+00:00"))
        if premium_until.tzinfo is None:
            premium_until = premium_until.replace(tzinfo=timezone.utc)
    elif data.duration_minutes and data.duration_minutes > 0:
        premium_until = now_utc() + timedelta(minutes=int(data.duration_minutes))
    else:
        # Alteração manual sem data: torna permanente.
        permanent = True

    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.id == data.user_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        role = "admin" if plan == "admin" else row_dict(found).get("role", "user")
        conn.execute(
            update(users)
            .where(users.c.id == data.user_id)
            .values(plan=plan, role=role, premium_until=premium_until, permanent=permanent, updated_at=now_utc())
        )
        add_admin_log(conn, admin["id"], "user_plan_changed", str(data.user_id), f"plan={plan}; permanent={permanent}")

    return {
        "message": "Plano alterado com sucesso",
        "user_id": data.user_id,
        "plan": plan,
        "plan_name": public_plan_name(plan),
        "premium_until": serialize_dt(premium_until),
        "permanent": permanent,
    }


@app.post("/admin/users/ban")
def ban_user(data: BanUserRequest, admin: Dict[str, Any] = Depends(require_admin)):
    level = str(data.level or "leve").strip().casefold()
    allowed = {
        "aviso": None,
        "leve": 24 * 60,
        "medio": 7 * 24 * 60,
        "médio": 7 * 24 * 60,
        "grave": 30 * 24 * 60,
        "permanente": None,
    }
    if level not in allowed:
        raise HTTPException(status_code=400, detail="Nível de ban inválido")

    message = str(data.message or "Conta suspensa pelo administrador.").strip()[:1000]
    duration = data.duration_minutes if data.duration_minutes is not None else allowed[level]
    banned_until = None if duration in (None, 0, -1) else now_utc() + timedelta(minutes=int(duration))
    disabled = level != "aviso"

    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.id == data.user_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        target = row_dict(found)
        if is_admin(target):
            raise HTTPException(status_code=400, detail="Não é permitido banir uma conta admin")
        conn.execute(
            update(users)
            .where(users.c.id == data.user_id)
            .values(
                disabled=disabled,
                ban_level=level,
                ban_message=message,
                banned_until=banned_until,
                updated_at=now_utc(),
            )
        )
        add_admin_log(conn, admin["id"], "user_banned" if disabled else "user_warned", str(data.user_id), f"level={level}; message={message}; until={serialize_dt(banned_until)}")

    return {
        "message": "Usuário banido" if disabled else "Aviso registrado",
        "user_id": data.user_id,
        "level": level,
        "ban_message": message,
        "banned_until": serialize_dt(banned_until),
        "disabled": disabled,
    }


@app.post("/admin/users/unban")
def unban_user(data: UserIdRequest, admin: Dict[str, Any] = Depends(require_admin)):
    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.id == data.user_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        conn.execute(
            update(users)
            .where(users.c.id == data.user_id)
            .values(disabled=False, ban_level=None, ban_message=None, banned_until=None, updated_at=now_utc())
        )
        add_admin_log(conn, admin["id"], "user_unbanned", str(data.user_id), "Conta desbloqueada")
    return {"message": "Conta desbloqueada", "user_id": data.user_id}


@app.post("/admin/users/revoke-plan")
def revoke_user_plan(data: RevokePlanRequest, admin: Dict[str, Any] = Depends(require_admin)):
    message = str(data.message or "Plano revogado pelo administrador.").strip()[:1000]
    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.id == data.user_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        target = row_dict(found)
        if is_admin(target):
            raise HTTPException(status_code=400, detail="Não é permitido revogar plano de uma conta admin")
        conn.execute(
            update(users)
            .where(users.c.id == data.user_id)
            .values(plan="free", premium_until=None, permanent=False, updated_at=now_utc())
        )
        add_admin_log(conn, admin["id"], "user_plan_revoked", str(data.user_id), message)
        add_app_log(conn, data.user_id, "plan_revoked_by_admin", message)
    return {"message": "Plano revogado", "user_id": data.user_id, "admin_message": message}


@app.post("/admin/users/delete")
@app.delete("/admin/users/delete")
def delete_user(data: UserIdRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if int(data.user_id) == int(admin["id"]):
        raise HTTPException(status_code=400, detail="Não é permitido excluir a própria conta admin")
    with engine.begin() as conn:
        found = conn.execute(select(users).where(users.c.id == data.user_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        target = row_dict(found)
        if is_admin(target):
            raise HTTPException(status_code=400, detail="Não é permitido excluir outra conta admin por esta rota")
        conn.execute(sessions.delete().where(sessions.c.user_id == data.user_id))
        conn.execute(update(license_keys).where(license_keys.c.used_by == data.user_id).values(used_by=None, is_used=False, used_at=None))
        conn.execute(user_themes.delete().where(user_themes.c.user_id == data.user_id))
        conn.execute(theme_orders.delete().where(theme_orders.c.user_id == data.user_id))
        conn.execute(app_logs.delete().where(app_logs.c.user_id == data.user_id))
        conn.execute(users.delete().where(users.c.id == data.user_id))
        add_admin_log(conn, admin["id"], "user_deleted", str(data.user_id), f"username={target.get('username')}")
    return {"message": "Conta excluída", "user_id": data.user_id}


@app.post("/admin/keys/delete")
@app.delete("/admin/keys/delete")
def delete_key(data: DeleteKeyRequest, admin: Dict[str, Any] = Depends(require_admin)):
    if data.key_id is None and not data.key_code:
        raise HTTPException(status_code=400, detail="Informe key_id ou key_code")
    with engine.begin() as conn:
        condition = license_keys.c.id == data.key_id if data.key_id is not None else license_keys.c.key_code_hash == hash_text(data.key_code.strip())
        found = conn.execute(select(license_keys).where(condition)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Key não encontrada")
        key = row_dict(found)
        conn.execute(license_keys.delete().where(license_keys.c.id == key["id"]))
        add_admin_log(conn, admin["id"], "key_deleted", key["display_name"], f"id={key['id']}")
    return {"message": "Key excluída", "key_id": key["id"], "display_name": key["display_name"]}


@app.get("/admin/dashboard")
def admin_dashboard(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        total_users = int(conn.execute(select(func.count()).select_from(users)).scalar_one() or 0)
        disabled_users = int(conn.execute(select(func.count()).select_from(users).where(users.c.disabled == True)).scalar_one() or 0)  # noqa: E712
        user_rows = conn.execute(select(users.c.plan, users.c.permanent, users.c.premium_until)).fetchall()
        plan_counts = {"free": 0, "premium": 0, "patrocinador": 0, "admin": 0}
        for row in user_rows:
            payload = user_license_payload(row_dict(row))
            plan_counts[payload["plan"]] = plan_counts.get(payload["plan"], 0) + 1
        key_total = int(conn.execute(select(func.count()).select_from(license_keys)).scalar_one() or 0)
        key_used = int(conn.execute(select(func.count()).select_from(license_keys).where(license_keys.c.is_used == True)).scalar_one() or 0)  # noqa: E712
        key_revoked = int(conn.execute(select(func.count()).select_from(license_keys).where(license_keys.c.revoked == True)).scalar_one() or 0)  # noqa: E712
        beta_total = int(conn.execute(select(func.count()).select_from(beta_keys)).scalar_one() or 0)
        beta_access_orders_total = int(conn.execute(select(func.count()).select_from(beta_access_orders)).scalar_one() or 0)
        beta_access_orders_delivered = int(conn.execute(select(func.count()).select_from(beta_access_orders).where(beta_access_orders.c.status == "delivered")).scalar_one() or 0)
        orders_total = int(conn.execute(select(func.count()).select_from(orders)).scalar_one() or 0)
        orders_pending = int(conn.execute(select(func.count()).select_from(orders).where(orders.c.status.in_(["pending", "payment_pending"]))).scalar_one() or 0)
        orders_delivered = int(conn.execute(select(func.count()).select_from(orders).where(orders.c.status == "delivered")).scalar_one() or 0)
        revenue_cents = int(conn.execute(select(func.coalesce(func.sum(orders.c.price_cents), 0)).where(orders.c.status == "delivered")).scalar_one() or 0)
        themes_total = int(conn.execute(select(func.count()).select_from(themes)).scalar_one() or 0)
        themes_active = int(conn.execute(select(func.count()).select_from(themes).where(themes.c.is_active == True)).scalar_one() or 0)  # noqa: E712
        theme_orders_total = int(conn.execute(select(func.count()).select_from(theme_orders)).scalar_one() or 0)
        theme_orders_pending = int(conn.execute(select(func.count()).select_from(theme_orders).where(theme_orders.c.status.in_(["pending", "payment_pending"]))).scalar_one() or 0)
        theme_orders_delivered = int(conn.execute(select(func.count()).select_from(theme_orders).where(theme_orders.c.status == "delivered")).scalar_one() or 0)
        themes_revenue_cents = int(conn.execute(select(func.coalesce(func.sum(theme_orders.c.price_cents), 0)).where(theme_orders.c.status == "delivered")).scalar_one() or 0)
        tickets_open = int(conn.execute(select(func.count()).select_from(support_tickets).where(support_tickets.c.status.in_(["aberto", "em_analise"]))).scalar_one() or 0)
        security_recent = int(conn.execute(select(func.count()).select_from(security_events).where(security_events.c.created_at >= now_utc() - timedelta(hours=24))).scalar_one() or 0)
        latest_tickets = conn.execute(
            select(support_tickets, users.c.username)
            .select_from(support_tickets.outerjoin(users, users.c.id == support_tickets.c.user_id))
            .order_by(support_tickets.c.id.desc())
            .limit(5)
        ).fetchall()
    return {
        "users": {"total": total_users, "disabled": disabled_users, **plan_counts},
        "keys": {"total": key_total, "used": key_used, "available": max(0, key_total - key_used - key_revoked), "revoked": key_revoked},
        "beta": {"total": beta_total, "access_orders": beta_access_orders_total, "access_delivered": beta_access_orders_delivered},
        "orders": {"total": orders_total, "pending": orders_pending, "delivered": orders_delivered, "revenue_cents": revenue_cents, "revenue_label": price_label(revenue_cents)},
        "themes": {
            "total": themes_total,
            "active": themes_active,
            "orders_total": theme_orders_total,
            "orders_pending": theme_orders_pending,
            "orders_delivered": theme_orders_delivered,
            "revenue_cents": themes_revenue_cents,
            "revenue_label": price_label(themes_revenue_cents),
        },
        "support": {"open": tickets_open, "latest": [serialize_ticket(row, username=row_dict(row).get("username")) for row in latest_tickets]},
        "security": {"events_24h": security_recent},
        "server": {"version": APP_VERSION, "payment_provider": PAYMENT_PROVIDER, "mercadopago_configured": bool(MERCADOPAGO_ACCESS_TOKEN), "time": serialize_dt(now_utc())},
    }


@app.get("/admin/support/tickets")
def admin_support_tickets(status: str = Query("todos"), admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        query = (
            select(support_tickets, users.c.username)
            .select_from(support_tickets.outerjoin(users, users.c.id == support_tickets.c.user_id))
            .order_by(support_tickets.c.id.desc())
            .limit(300)
        )
        if status and status != "todos":
            query = query.where(support_tickets.c.status == status)
        rows = conn.execute(query).fetchall()
    return {"tickets": [serialize_ticket(row, username=row_dict(row).get("username")) for row in rows]}


@app.post("/admin/support/tickets/update")
def admin_update_support_ticket(data: SupportUpdateRequest, admin: Dict[str, Any] = Depends(require_admin)):
    status = str(data.status or "em_analise").strip().casefold()
    allowed = {"aberto", "em_analise", "resolvido", "fechado"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail="Status inválido")
    with engine.begin() as conn:
        found = conn.execute(select(support_tickets).where(support_tickets.c.id == data.ticket_id)).first()
        if not found:
            raise HTTPException(status_code=404, detail="Ticket não encontrado")
        conn.execute(
            update(support_tickets)
            .where(support_tickets.c.id == data.ticket_id)
            .values(status=status, admin_message=safe_details(data.admin_message), updated_at=now_utc())
        )
        ticket = row_dict(found)
        add_admin_log(conn, admin["id"], "support_ticket_updated", str(data.ticket_id), f"status={status}")
        if ticket.get("user_id"):
            add_app_log(conn, ticket.get("user_id"), "support_ticket_updated", f"ticket=#{data.ticket_id}; status={status}; {safe_details(data.admin_message)}")
    return {"message": "Ticket atualizado", "ticket_id": data.ticket_id, "status": status}


@app.get("/admin/logs")
def list_admin_logs(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(admin_logs).order_by(admin_logs.c.id.desc()).limit(300)).fetchall()
    return {
        "logs": [
            {
                **{k: v for k, v in row_dict(row).items() if k != "created_at"},
                "created_at": serialize_dt(row_dict(row).get("created_at")),
            }
            for row in rows
        ]
    }


@app.post("/logs/create")
def create_log(data: LogRequest, user: Dict[str, Any] = Depends(get_user_by_token)):
    with engine.begin() as conn:
        add_app_log(conn, user["id"], data.action, data.details)
    return {"message": "Log salvo com sucesso"}


@app.get("/admin/app-logs")
def list_app_logs(admin: Dict[str, Any] = Depends(require_admin)):
    with engine.connect() as conn:
        rows = conn.execute(select(app_logs).order_by(app_logs.c.id.desc()).limit(300)).fetchall()
    return {
        "logs": [
            {
                **{k: v for k, v in row_dict(row).items() if k != "created_at"},
                "created_at": serialize_dt(row_dict(row).get("created_at")),
            }
            for row in rows
        ]
    }
