"""Email-seeded modules."""
from __future__ import annotations

import csv
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from ..config import HIBP_API_KEY, MODULE_TIMEOUT, TOOLS
from ..schemas import (
    CONF_CONFIRMED, CONF_DERIVED, CONF_STRONG, Edge, Entity, Finding,
    ModuleResult, make_id,
)
from .base import Module, http_client, register, run_cli, safe_json

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "temp-mail.org", "trashmail.com",
    "getnada.com", "sharklasers.com", "maildrop.cc", "fakeinbox.com",
    "dispostable.com", "mintemail.com", "moakt.com", "emailondeck.com",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "mail.ru", "yandex.com", "zoho.com",
}

ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "contact", "hello", "help",
    "noreply", "no-reply", "webmaster", "postmaster", "abuse", "billing",
}


# ---------------------------------------------------------------------------
@register
class EmailProfile(Module):
    name = "email_profile"
    title = "بنية البريد و DNS"
    accepts = {"email"}
    category = "identity"
    description = "تحقق من الصيغة، سجلات MX، نوع النطاق، واشتقاق اسم المستخدم"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        email = target.strip().lower()

        if not EMAIL_RE.match(email):
            res.status = "error"
            res.error = "صيغة البريد غير صالحة"
            return res

        local, _, domain = email.partition("@")
        email_id = make_id("email", email)

        # derived username - explicitly low confidence, it is a guess
        username = re.sub(r"[+].*$", "", local)
        if len(username) >= 3:
            u = Entity(
                type="username", value=username, source=self.name,
                confidence=CONF_DERIVED,
                meta={"origin": "مشتق من الجزء المحلي للبريد"},
            )
            res.entities.append(u)
            res.edges.append(Edge(email_id, u.id, "derived_username", CONF_DERIVED, self.name))

        d = Entity(type="domain", value=domain, source=self.name, confidence=CONF_CONFIRMED)
        res.entities.append(d)
        res.edges.append(Edge(email_id, d.id, "uses_domain", CONF_CONFIRMED, self.name))

        # classification
        kind = "نطاق خاص"
        if domain in DISPOSABLE:
            kind = "بريد مؤقت"
        elif domain in FREEMAIL:
            kind = "بريد مجاني"
        is_role = local.split("+")[0] in ROLE_PREFIXES

        res.findings.append(Finding(
            module=self.name, category="identity",
            title=f"تصنيف النطاق: {kind}",
            detail=f"النطاق {domain}" + ("  ·  حساب وظيفي وليس شخصياً" if is_role else ""),
            severity="notable" if kind == "بريد مؤقت" else "info",
            raw={"domain": domain, "kind": kind, "role_account": is_role},
        ))

        # MX records
        mx_hosts: list[str] = []
        try:
            import dns.asyncresolver
            answers = await dns.asyncresolver.resolve(domain, "MX")
            mx_hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
        except Exception as exc:  # noqa: BLE001
            res.findings.append(Finding(
                module=self.name, category="identity",
                title="تعذّر جلب سجلات MX",
                detail=str(exc), severity="notable",
            ))
        if mx_hosts:
            provider = _guess_provider(mx_hosts)
            res.findings.append(Finding(
                module=self.name, category="identity",
                title=f"البريد يُستضاف عبر: {provider}",
                detail=" · ".join(mx_hosts[:4]),
                raw={"mx": mx_hosts},
            ))
            ctx.setdefault("hints", {})["mail_provider"] = provider

        return res


def _guess_provider(mx: list[str]) -> str:
    joined = " ".join(mx).lower()
    table = [
        ("google", "Google Workspace"), ("outlook", "Microsoft 365"),
        ("protection.outlook", "Microsoft 365"), ("zoho", "Zoho Mail"),
        ("yandex", "Yandex"), ("proton", "Proton Mail"),
        ("mimecast", "Mimecast"), ("yahoodns", "Yahoo"),
        ("icloud", "Apple iCloud"), ("mailgun", "Mailgun"),
        ("amazonaws", "Amazon SES"), ("titan", "Titan"),
    ]
    for needle, label in table:
        if needle in joined:
            return label
    return mx[0] if mx else "غير معروف"


# ---------------------------------------------------------------------------
@register
class Gravatar(Module):
    name = "gravatar"
    title = "Gravatar"
    accepts = {"email"}
    category = "identity"
    description = "صورة رمزية وملف عام مرتبط ببصمة البريد"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        email = target.strip().lower()
        digest = hashlib.md5(email.encode()).hexdigest()
        email_id = make_id("email", email)
        avatar_url = f"https://www.gravatar.com/avatar/{digest}?s=400&d=404"

        async with http_client() as client:
            head = await client.get(avatar_url)
            if head.status_code != 200:
                return res  # -> "empty"

            img = Entity(
                type="image", value=avatar_url, label="صورة Gravatar",
                source=self.name, confidence=CONF_STRONG, url=avatar_url,
            )
            res.entities.append(img)
            res.edges.append(Edge(email_id, img.id, "has_avatar", CONF_STRONG, self.name))
            res.findings.append(Finding(
                module=self.name, category="identity",
                title="يوجد Gravatar مرتبط بهذا البريد",
                detail="وجود الصورة يؤكد أن البريد مُستخدم فعلياً",
                url=avatar_url, confidence=CONF_STRONG, severity="notable",
            ))

            prof = await client.get(f"https://www.gravatar.com/{digest}.json")
            data = safe_json(prof.text) if prof.status_code == 200 else None

        entries = (data or {}).get("entry") or []
        if not entries:
            return res

        entry = entries[0]
        display = entry.get("displayName") or entry.get("preferredUsername")
        if display:
            p = Entity(type="person", value=display, source=self.name, confidence=CONF_STRONG)
            res.entities.append(p)
            res.edges.append(Edge(email_id, p.id, "identifies_as", CONF_STRONG, self.name))
            res.findings.append(Finding(
                module=self.name, category="identity",
                title=f"الاسم المعروض: {display}",
                confidence=CONF_STRONG, severity="notable",
            ))

        handle = entry.get("preferredUsername")
        if handle:
            u = Entity(type="username", value=handle, source=self.name, confidence=CONF_STRONG,
                       meta={"origin": "معلن في ملف Gravatar"})
            res.entities.append(u)
            res.edges.append(Edge(email_id, u.id, "username", CONF_STRONG, self.name))

        for acct in entry.get("accounts") or []:
            url = acct.get("url")
            shortname = acct.get("shortname") or acct.get("domain") or "حساب"
            if not url:
                continue
            a = Entity(type="account", value=url, label=f"{shortname}", source=self.name,
                       confidence=CONF_STRONG, url=url, meta={"service": shortname})
            res.entities.append(a)
            res.edges.append(Edge(email_id, a.id, "has_account", CONF_STRONG, self.name))
            res.findings.append(Finding(
                module=self.name, category="accounts",
                title=f"حساب معلن: {shortname}", url=url, confidence=CONF_STRONG,
            ))

        for key in ("aboutMe", "currentLocation"):
            if entry.get(key):
                res.findings.append(Finding(
                    module=self.name, category="identity",
                    title="الموقع" if key == "currentLocation" else "نبذة",
                    detail=str(entry[key])[:400], confidence=CONF_STRONG,
                ))
        return res


# ---------------------------------------------------------------------------
@register
class Holehe(Module):
    name = "holehe"
    title = "holehe — تسجيل الحسابات"
    accepts = {"email"}
    category = "accounts"
    description = "يفحص ~120 موقعاً لمعرفة إن كان البريد مسجلاً فيها"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        binary = TOOLS.get("holehe")
        if not binary:
            res.status = "not_configured"
            res.note = "holehe غير مثبّت — pip install holehe"
            return res

        email = target.strip().lower()
        email_id = make_id("email", email)

        with tempfile.TemporaryDirectory() as tmp:
            argv = [binary, email, "--only-used", "--no-color", "--no-clear", "-C"]
            code, out, err = await run_cli(argv, timeout=MODULE_TIMEOUT, cwd=tmp)
            rows = _read_holehe_csv(Path(tmp))

        if not rows and code != 0:
            res.status = "error"
            res.error = (err or out or "فشل التنفيذ").strip()[:300]
            return res

        for row in rows:
            if str(row.get("exists", "")).strip().lower() != "true":
                continue
            site = (row.get("name") or row.get("domain") or "").strip()
            if not site:
                continue
            domain = (row.get("domain") or site).strip()
            url = f"https://{domain}" if domain and "." in domain else None
            a = Entity(type="account", value=f"{site}:{email}", label=site, source=self.name,
                       confidence=CONF_CONFIRMED, url=url, meta={"service": site})
            res.entities.append(a)
            res.edges.append(Edge(email_id, a.id, "registered_on", CONF_CONFIRMED, self.name))

            hints = []
            if row.get("emailrecovery"):
                hints.append(f"بريد استرجاع جزئي: {row['emailrecovery']}")
            if row.get("phoneNumber"):
                hints.append(f"هاتف جزئي: {row['phoneNumber']}")
                res.findings.append(Finding(
                    module=self.name, category="accounts",
                    title=f"{site} يكشف جزءاً من رقم الهاتف",
                    detail=str(row["phoneNumber"]), severity="high",
                ))
            res.findings.append(Finding(
                module=self.name, category="accounts",
                title=f"البريد مسجّل في {site}",
                detail=" · ".join(hints), url=url,
                severity="notable" if hints else "info",
                raw=dict(row),
            ))

        if not res.findings:
            res.note = "لم يُعثر على حسابات — قد يعني أيضاً أن المواقع طبّقت حدّ معدل"
        return res


def _read_holehe_csv(folder: Path) -> list[dict[str, str]]:
    files = sorted(folder.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in files:
        try:
            with path.open(newline="", encoding="utf-8", errors="replace") as fh:
                return list(csv.DictReader(fh))
        except OSError:
            continue
    return []


# ---------------------------------------------------------------------------
@register
class Breaches(Module):
    name = "breaches"
    title = "التسريبات"
    accepts = {"email"}
    category = "breaches"
    description = "XposedOrNot و LeakCheck مجاناً، و HIBP إذا توفّر مفتاح"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        email = target.strip().lower()
        email_id = make_id("email", email)
        seen: set[str] = set()

        def add_breach(name: str, source: str, detail: str = "", meta: dict | None = None) -> None:
            key = name.strip().lower()
            if not key or key in seen:
                return
            seen.add(key)
            b = Entity(type="breach", value=name, source=source, confidence=CONF_CONFIRMED,
                       meta=meta or {})
            res.entities.append(b)
            res.edges.append(Edge(email_id, b.id, "leaked_in", CONF_CONFIRMED, source))
            res.findings.append(Finding(
                module=self.name, category="breaches",
                title=f"ظهر في تسريب: {name}", detail=detail,
                severity="high", raw=meta or {}, url=(meta or {}).get("url"),
            ))

        async with http_client() as client:
            # --- XposedOrNot (free, no key) ---
            try:
                r = await client.get(f"https://api.xposedornot.com/v1/check-email/{email}")
                data = safe_json(r.text) or {}
                groups = data.get("breaches") or []
                for group in groups:
                    for name in (group if isinstance(group, list) else [group]):
                        add_breach(str(name), "xposedornot")
            except Exception as exc:  # noqa: BLE001
                res.note += f"XposedOrNot: {exc}؛ "

            # --- LeakCheck public (free, no key, no passwords returned) ---
            try:
                r = await client.get("https://leakcheck.io/api/public", params={"check": email})
                data = safe_json(r.text) or {}
                if data.get("success"):
                    for src in data.get("sources", []) or []:
                        nm = src.get("name") if isinstance(src, dict) else str(src)
                        date = src.get("date", "") if isinstance(src, dict) else ""
                        add_breach(str(nm), "leakcheck", detail=f"تاريخ التسريب: {date}" if date else "")
                    fields = data.get("fields") or []
                    if fields:
                        res.findings.append(Finding(
                            module=self.name, category="breaches",
                            title="أنواع البيانات المسرّبة",
                            detail="، ".join(map(str, fields)), severity="high",
                        ))
            except Exception as exc:  # noqa: BLE001
                res.note += f"LeakCheck: {exc}؛ "

            # --- HIBP (optional, paid key) ---
            if HIBP_API_KEY:
                try:
                    r = await client.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                        params={"truncateResponse": "false"},
                        headers={"hibp-api-key": HIBP_API_KEY},
                    )
                    if r.status_code == 200:
                        for b in safe_json(r.text) or []:
                            add_breach(
                                b.get("Name", "?"), "hibp",
                                detail=f"{b.get('BreachDate','')} · {b.get('PwnCount',0):,} حساب",
                                meta={
                                    "classes": b.get("DataClasses", []),
                                    "date": b.get("BreachDate"),
                                    "count": b.get("PwnCount"),
                                    "verified": b.get("IsVerified"),
                                },
                            )
                    elif r.status_code == 401:
                        res.note += "مفتاح HIBP مرفوض؛ "
                except Exception as exc:  # noqa: BLE001
                    res.note += f"HIBP: {exc}؛ "
            else:
                res.note += "HIBP معطّل (لا يوجد مفتاح)؛ "

        if seen:
            res.findings.insert(0, Finding(
                module=self.name, category="breaches",
                title=f"إجمالي التسريبات المعروفة: {len(seen)}",
                detail="يُنصح بتغيير كلمات المرور وتفعيل التحقق بخطوتين",
                severity="high",
            ))
        return res
