"""Schémas Pydantic : toute entrée utilisateur est validée ici."""
import re

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.config import DOMAINS

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def _check_password(v: str) -> str:
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        raise ValueError("Le mot de passe doit contenir au moins une lettre et un chiffre.")
    return v


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    domain: str = "autre"

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_RE.match(v):
            raise ValueError("Pseudo : 3 à 32 caractères (lettres, chiffres, _ . -).")
        return v

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return _check_password(v)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        if v not in DOMAINS:
            raise ValueError("Domaine inconnu.")
        return v


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ForgotIn(BaseModel):
    username: str = Field(min_length=1, max_length=254)


class ResetIn(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return _check_password(v)


class ContactIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    subject: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=5, max_length=5000)
    website: str = ""  # honeypot : doit rester vide


class ProfileUpdate(BaseModel):
    display_name: str = Field(default="", max_length=64)
    bio: str = Field(default="", max_length=500)
    domain: str = "autre"
