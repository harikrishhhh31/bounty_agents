from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Iterable


@dataclass(frozen=True, slots=True)
class ProgramPolicy:
    program_name: str
    own_accounts_only: bool | None = None
    allowed_auth_account_requirements: tuple[str, ...] = ()
    prohibited_testing_categories: tuple[str, ...] = ()
    third_party_restriction: bool | None = None
    dos_prohibited: bool | None = None
    social_engineering_prohibited: bool | None = None
    poc_requirement: bool | None = None
    disclosure_restrictions: tuple[str, ...] = ()
    reporting_requirements: tuple[str, ...] = ()
    manual_attention: tuple[str, ...] = ()
    raw_markdown_reference: str = ""
    raw_markdown: str = field(repr=False, default="")

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["raw_markdown"] = self.raw_markdown
        return value


def parse_program_markdown(markdown: str, *, source: str = "") -> ProgramPolicy:
    lines = [line.strip() for line in markdown.splitlines()]
    program_name = next((line.lstrip("#").strip() for line in lines if line.startswith("#") and line.lstrip("#").strip()), "Unnamed program")
    lowered = markdown.lower()
    own_accounts = _contains_any(lowered, ("own accounts", "your own account", "researcher accounts", "accounts you control"))
    third_party = _contains_any(lowered, ("third-party", "third party", "third party services")) and _contains_any(lowered, ("do not", "prohibited", "not allowed", "out of scope", "only"))
    dos = _contains_any(lowered, ("denial of service", "denial-of-service", "dos")) and _contains_any(lowered, ("do not", "prohibited", "not allowed", "out of scope"))
    social = _contains_any(lowered, ("social engineering", "phishing")) and _contains_any(lowered, ("do not", "prohibited", "not allowed", "out of scope"))
    poc = _contains_any(lowered, ("proof of concept", "poc", "reproduction steps", "reproduction instructions")) and _contains_any(lowered, ("required", "include", "must", "should provide"))
    prohibited = tuple(_matching_categories(lowered))
    disclosure = tuple(line for line in lines if _is_disclosure_rule(line))
    reporting = tuple(line for line in lines if _is_reporting_rule(line))
    account_requirements = tuple(line for line in lines if _is_account_rule(line))
    recognized = set(disclosure) | set(reporting) | set(account_requirements)
    manual = tuple(line for line in lines if _needs_manual_attention(line) and line not in recognized)
    return ProgramPolicy(program_name, own_accounts, account_requirements, prohibited, third_party, dos, social, poc, disclosure, reporting, manual, source, markdown)


def _contains_any(value: str, terms: Iterable[str]) -> bool:
    return any(term in value for term in terms)


def _matching_categories(value: str) -> list[str]:
    categories: list[str] = []
    for label, terms in (("denial_of_service", ("denial of service", "denial-of-service")), ("social_engineering", ("social engineering", "phishing")), ("third_party_testing", ("third-party", "third party"))):
        if _contains_any(value, terms) and _contains_any(value, ("do not", "prohibited", "not allowed", "out of scope")):
            categories.append(label)
    return categories


def _is_disclosure_rule(line: str) -> bool:
    value = line.lower()
    return _contains_any(value, ("disclos", "publicly", "coordinat")) and _contains_any(value, ("must", "do not", "before", "only", "not"))


def _is_reporting_rule(line: str) -> bool:
    value = line.lower()
    return _contains_any(value, ("report", "reproduction", "proof of concept", "poc")) and _contains_any(value, ("must", "include", "required", "should"))


def _is_account_rule(line: str) -> bool:
    value = line.lower()
    return _contains_any(value, ("account", "authentication", "authenticated")) and _contains_any(value, ("own", "your", "must", "required"))


def _needs_manual_attention(line: str) -> bool:
    value = line.lower()
    return bool(line) and not line.startswith(("#", "-", "*", ">")) and _contains_any(value, ("manual", "case-by-case", "contact", "may", "unless", "where applicable", "anything else"))


__all__ = ["ProgramPolicy", "parse_program_markdown"]
