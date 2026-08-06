"""OSINT Suite Lite — Vercel serverless edition.

Deliberately one file. Vercel's Python runtime bundles a function by static
analysis of its entry point; a single module removes every question about what
does or does not get included.

What changed versus the Docker build:
  * No subprocess tools (holehe / maigret / ghunt) — they need minutes and
    conflicting virtualenvs, neither of which exists here.
  * No SQLite, no job queue, no polling. A scan is one request in, one full
    report out, because every remaining module finishes in seconds.
  * DNS runs over HTTPS instead of dnspython. UDP:53 out of Lambda is not
    dependable, and DoH also drops a dependency from the bundle.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ===========================================================================
# config
# ===========================================================================
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "8"))
SCAN_BUDGET = float(os.getenv("SCAN_BUDGET", "45"))   # keep under maxDuration
USER_AGENT = os.getenv("USER_AGENT", "osint-suite-lite/1.0 (self-hosted research)")

CONF_CONFIRMED, CONF_STRONG, CONF_DERIVED, CONF_WEAK = 1.0, 0.8, 0.5, 0.3


# ===========================================================================
# data model
# ===========================================================================
def make_id(etype: str, value: str) -> str:
    return hashlib.sha1(f"{etype}:{value.strip().lower()}".encode()).hexdigest()[:16]


@dataclass
class Entity:
    type: str
    value: str
    label: str = ""
    confidence: float = CONF_CONFIRMED
    source: str = ""
    url: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        self.id = self.id or make_id(self.type, self.value)
        self.label = self.label or self.value


@dataclass
class Edge:
    source: str
    target: str
    relation: str
    confidence: float = CONF_CONFIRMED
    module: str = ""


@dataclass
class Finding:
    module: str
    category: str
    title: str
    detail: str = ""
    url: str | None = None
    confidence: float = CONF_CONFIRMED
    severity: Literal["info", "notable", "high"] = "info"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Result:
    module: str
    status: str = "ok"
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    note: str = ""
    duration: float = 0.0


# ===========================================================================
# DNS over HTTPS
# ===========================================================================
RTYPE = {"A": 1, "NS": 2, "TXT": 16, "MX": 15}
DOH_ENDPOINTS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


async def doh(client: httpx.AsyncClient, name: str, rtype: str) -> list[str]:
    """Resolve over HTTPS. Returns record data strings, empty list on failure."""
    want = RTYPE[rtype]
    for base in DOH_ENDPOINTS:
        try:
            r = await client.get(
                base, params={"name": name, "type": rtype},
                headers={"accept": "application/dns-json"},
            )
            if r.status_code != 200:
                continue
            answers = (r.json() or {}).get("Answer") or []
            out = [str(a.get("data", "")).strip('"') for a in answers if a.get("type") == want]
            if out:
                return out
        except Exception:  # noqa: BLE001 - try the next resolver
            continue
    return []


def parse_mx(records: list[str]) -> list[str]:
    """DoH returns MX as '10 mail.example.com.' — sort by priority, strip dots."""
    parsed: list[tuple[int, str]] = []
    for rec in records:
        parts = rec.split()
        if len(parts) == 2 and parts[0].isdigit():
            parsed.append((int(parts[0]), parts[1].rstrip(".")))
        elif parts:
            parsed.append((999, parts[-1].rstrip(".")))
    return [host for _, host in sorted(parsed)]


# ===========================================================================
# module 1 — email structure & DNS
# ===========================================================================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{6,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")

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
PROVIDERS = [
    ("google", "Google Workspace"), ("protection.outlook", "Microsoft 365"),
    ("outlook", "Microsoft 365"), ("zoho", "Zoho Mail"), ("yandex", "Yandex"),
    ("proton", "Proton Mail"), ("mimecast", "Mimecast"), ("yahoodns", "Yahoo"),
    ("icloud", "Apple iCloud"), ("mailgun", "Mailgun"), ("amazonaws", "Amazon SES"),
    ("titan", "Titan"), ("secureserver", "GoDaddy"),
]


async def mod_email_profile(client: httpx.AsyncClient, target: str) -> Result:
    res = Result("email_profile")
    email = target.strip().lower()
    if not EMAIL_RE.match(email):
        res.status, res.error = "error", "صيغة البريد غير صالحة"
        return res

    local, _, domain = email.partition("@")
    eid = make_id("email", email)

    username = re.sub(r"\+.*$", "", local)
    if len(username) >= 3:
        u = Entity("username", username, source=res.module, confidence=CONF_DERIVED,
                   meta={"origin": "مشتق من الجزء المحلي للبريد"})
        res.entities.append(u)
        res.edges.append(Edge(eid, u.id, "derived_username", CONF_DERIVED, res.module))

    d = Entity("domain", domain, source=res.module)
    res.entities.append(d)
    res.edges.append(Edge(eid, d.id, "uses_domain", CONF_CONFIRMED, res.module))

    kind = "بريد مؤقت" if domain in DISPOSABLE else "بريد مجاني" if domain in FREEMAIL else "نطاق خاص"
    is_role = local.split("+")[0] in ROLE_PREFIXES
    res.findings.append(Finding(
        res.module, "identity", f"تصنيف النطاق: {kind}",
        detail=domain + ("  ·  حساب وظيفي وليس شخصياً" if is_role else ""),
        severity="notable" if kind == "بريد مؤقت" else "info",
        raw={"domain": domain, "kind": kind, "role_account": is_role},
    ))

    mx = parse_mx(await doh(client, domain, "MX"))
    if mx:
        joined = " ".join(mx).lower()
        provider = next((lbl for needle, lbl in PROVIDERS if needle in joined), mx[0])
        res.findings.append(Finding(
            res.module, "identity", f"البريد يُستضاف عبر: {provider}",
            detail=" · ".join(mx[:4]), raw={"mx": mx},
        ))
    else:
        res.findings.append(Finding(
            res.module, "identity", "لا توجد سجلات MX",
            detail="النطاق لا يستقبل بريداً — قد يكون العنوان غير صالح",
            severity="notable",
        ))
    return res


# ===========================================================================
# module 2 — Gravatar
# ===========================================================================
async def mod_gravatar(client: httpx.AsyncClient, target: str) -> Result:
    res = Result("gravatar")
    email = target.strip().lower()
    digest = hashlib.md5(email.encode()).hexdigest()
    eid = make_id("email", email)
    avatar = f"https://www.gravatar.com/avatar/{digest}?s=400&d=404"

    r = await client.get(avatar)
    if r.status_code != 200:
        res.status = "empty"
        return res

    img = Entity("image", avatar, "صورة Gravatar", CONF_STRONG, res.module, avatar)
    res.entities.append(img)
    res.edges.append(Edge(eid, img.id, "has_avatar", CONF_STRONG, res.module))
    res.findings.append(Finding(
        res.module, "identity", "يوجد Gravatar مرتبط بهذا البريد",
        detail="وجود الصورة يؤكد أن البريد مُستخدم فعلياً",
        url=avatar, confidence=CONF_STRONG, severity="notable",
    ))

    try:
        pr = await client.get(f"https://www.gravatar.com/{digest}.json")
        entry = ((pr.json() or {}).get("entry") or [{}])[0] if pr.status_code == 200 else {}
    except Exception:  # noqa: BLE001
        entry = {}
    if not entry:
        return res

    display = entry.get("displayName") or entry.get("preferredUsername")
    if display:
        p = Entity("person", str(display), source=res.module, confidence=CONF_STRONG)
        res.entities.append(p)
        res.edges.append(Edge(eid, p.id, "identifies_as", CONF_STRONG, res.module))
        res.findings.append(Finding(res.module, "identity", f"الاسم المعروض: {display}",
                                    confidence=CONF_STRONG, severity="notable"))

    if entry.get("preferredUsername"):
        u = Entity("username", str(entry["preferredUsername"]), source=res.module,
                   confidence=CONF_STRONG, meta={"origin": "معلن في ملف Gravatar"})
        res.entities.append(u)
        res.edges.append(Edge(eid, u.id, "username", CONF_STRONG, res.module))

    for acct in entry.get("accounts") or []:
        url = acct.get("url")
        if not url:
            continue
        name = acct.get("shortname") or acct.get("domain") or "حساب"
        a = Entity("account", url, str(name), CONF_STRONG, res.module, url, {"service": name})
        res.entities.append(a)
        res.edges.append(Edge(eid, a.id, "has_account", CONF_STRONG, res.module))
        res.findings.append(Finding(res.module, "accounts", f"حساب معلن: {name}",
                                    url=url, confidence=CONF_STRONG))

    for key, label in (("currentLocation", "الموقع"), ("aboutMe", "نبذة")):
        if entry.get(key):
            res.findings.append(Finding(res.module, "identity", label,
                                        detail=str(entry[key])[:400], confidence=CONF_STRONG))
    return res


# ===========================================================================
# module 3 — breaches
# ===========================================================================
async def mod_breaches(client: httpx.AsyncClient, target: str) -> Result:
    res = Result("breaches")
    email = target.strip().lower()
    eid = make_id("email", email)
    seen: dict[str, Entity] = {}

    def add(name: str, source: str, detail: str = "", meta: dict | None = None) -> None:
        key = name.strip().lower()
        if not key:
            return
        if key in seen:
            # Same breach reported by a second feed - that is corroboration, not noise.
            ent = seen[key]
            srcs = sorted(set(ent.meta.get("sources", [])) | {source})
            ent.meta["sources"] = srcs
            ent.meta["corroboration"] = len(srcs)
            return
        b = Entity("breach", name, source=source,
                   meta={**(meta or {}), "sources": [source], "corroboration": 1})
        seen[key] = b
        res.entities.append(b)
        res.edges.append(Edge(eid, b.id, "leaked_in", CONF_CONFIRMED, source))
        res.findings.append(Finding(res.module, "breaches", f"ظهر في تسريب: {name}",
                                    detail=detail, severity="high", raw=meta or {}))

    try:
        r = await client.get(f"https://api.xposedornot.com/v1/check-email/{email}")
        for group in (r.json() or {}).get("breaches") or []:
            for name in (group if isinstance(group, list) else [group]):
                add(str(name), "xposedornot")
    except Exception as exc:  # noqa: BLE001
        res.note += f"XposedOrNot: {type(exc).__name__}؛ "

    try:
        r = await client.get("https://leakcheck.io/api/public", params={"check": email})
        data = r.json() or {}
        if data.get("success"):
            for src in data.get("sources") or []:
                nm = src.get("name") if isinstance(src, dict) else str(src)
                dt = src.get("date", "") if isinstance(src, dict) else ""
                add(str(nm), "leakcheck", detail=f"تاريخ التسريب: {dt}" if dt else "")
            if data.get("fields"):
                res.findings.append(Finding(
                    res.module, "breaches", "أنواع البيانات المسرّبة",
                    detail="، ".join(map(str, data["fields"])), severity="high",
                ))
    except Exception as exc:  # noqa: BLE001
        res.note += f"LeakCheck: {type(exc).__name__}؛ "

    if HIBP_API_KEY:
        try:
            r = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": HIBP_API_KEY},
            )
            if r.status_code == 200:
                for b in r.json() or []:
                    add(b.get("Name", "?"), "hibp",
                        detail=f"{b.get('BreachDate','')} · {b.get('PwnCount',0):,} حساب",
                        meta={"classes": b.get("DataClasses", []), "date": b.get("BreachDate"),
                              "count": b.get("PwnCount"), "verified": b.get("IsVerified")})
            elif r.status_code == 401:
                res.note += "مفتاح HIBP مرفوض؛ "
        except Exception as exc:  # noqa: BLE001
            res.note += f"HIBP: {type(exc).__name__}؛ "
    else:
        res.note += "HIBP معطّل (لا يوجد مفتاح)؛ "

    if seen:
        multi = [e.value for e in seen.values() if e.meta.get("corroboration", 1) > 1]
        detail = "يُنصح بتغيير كلمات المرور وتفعيل التحقق بخطوتين"
        if multi:
            detail += f"  ·  مؤكَّد من أكثر من مصدر: {'، '.join(multi)}"
        res.findings.insert(0, Finding(
            res.module, "breaches", f"إجمالي التسريبات المعروفة: {len(seen)}",
            detail=detail, severity="high", raw={"corroborated": multi},
        ))
    else:
        res.status = "empty"
    return res


# ===========================================================================
# module 4 — phone
# ===========================================================================
LINE_TYPES = {
    0: "خط أرضي", 1: "جوال", 2: "أرضي أو جوال", 3: "رقم مجاني", 4: "رقم مدفوع",
    5: "تكلفة مشتركة", 6: "VoIP", 7: "رقم شخصي", 8: "نداء آلي", 9: "UAN",
    10: "غير معروف", 27: "بريد صوتي",
}


async def mod_phone(client: httpx.AsyncClient, target: str, region: str | None = None) -> Result:
    res = Result("phone_profile")
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    try:
        num = phonenumbers.parse(target.strip(), region)
    except phonenumbers.NumberParseException as exc:
        res.status, res.error = "error", f"تعذّر تحليل الرقم: {exc}"
        return res

    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    pid = make_id("phone", e164)
    valid = phonenumbers.is_valid_number(num)
    country = geocoder.description_for_number(num, "ar") or geocoder.description_for_number(num, "en")
    net = carrier.name_for_number(num, "en")
    zones = list(timezone.time_zones_for_number(num))
    ltype = LINE_TYPES.get(phonenumbers.number_type(num), "غير معروف")

    res.entities.append(Entity("phone", e164, source=res.module,
                               meta={"valid": valid, "carrier": net, "region": country}))
    res.findings.append(Finding(
        res.module, "phone", f"الرقم {'صالح' if valid else 'غير صالح'} — {e164}",
        detail="دولي: " + phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        severity="info" if valid else "notable", raw={"valid": valid},
    ))
    if country:
        res.findings.append(Finding(res.module, "phone", f"المنطقة: {country}"))
    if net:
        res.findings.append(Finding(res.module, "phone", f"المشغّل عند الإصدار: {net}",
                                    detail="قد يتغيّر مع نقل الرقم بين الشبكات"))
    res.findings.append(Finding(res.module, "phone", f"نوع الخط: {ltype}"))
    if zones:
        res.findings.append(Finding(res.module, "phone", "المناطق الزمنية: " + "، ".join(zones)))
        for z in zones[:3]:
            loc = Entity("location", z, source=res.module, confidence=0.6)
            res.entities.append(loc)
            res.edges.append(Edge(pid, loc.id, "timezone", 0.6, res.module))
    return res


# ===========================================================================
# module 5 — domain infrastructure
# ===========================================================================
async def mod_domain(client: httpx.AsyncClient, target: str) -> Result:
    res = Result("domain_infra")
    domain = target.strip().lower().lstrip("@")
    did = make_id("domain", domain)

    a_rec, ns_rec, txt_rec, dmarc = await asyncio.gather(
        doh(client, domain, "A"), doh(client, domain, "NS"),
        doh(client, domain, "TXT"), doh(client, f"_dmarc.{domain}", "TXT"),
    )

    if a_rec:
        res.findings.append(Finding(res.module, "infra", "عناوين IP", detail=" · ".join(a_rec)))
        for ip in a_rec[:5]:
            e = Entity("url", ip, f"IP {ip}", source=res.module)
            res.entities.append(e)
            res.edges.append(Edge(did, e.id, "resolves_to", CONF_CONFIRMED, res.module))
    if ns_rec:
        res.findings.append(Finding(res.module, "infra", "خوادم الأسماء",
                                    detail=" · ".join(x.rstrip(".") for x in ns_rec)))

    spf = [t for t in txt_rec if t.lower().startswith("v=spf1")]
    if spf:
        res.findings.append(Finding(res.module, "infra", "سجل SPF", detail=spf[0][:300]))
    else:
        res.findings.append(Finding(res.module, "infra", "لا يوجد سجل SPF",
                                    detail="النطاق عرضة لانتحال البريد", severity="notable"))

    if dmarc:
        policy = "none"
        for part in dmarc[0].split(";"):
            if part.strip().startswith("p="):
                policy = part.split("=", 1)[1].strip()
        res.findings.append(Finding(
            res.module, "infra", f"سياسة DMARC: {policy}", detail=dmarc[0][:300],
            severity="notable" if policy == "none" else "info",
        ))
    else:
        res.findings.append(Finding(res.module, "infra", "لا يوجد سجل DMARC", severity="notable"))

    verif = [t for t in txt_rec if "verification" in t.lower() or "-site-" in t.lower()]
    if verif:
        res.findings.append(Finding(
            res.module, "infra", "خدمات مُتحقَّق منها على النطاق",
            detail=" · ".join(v[:60] for v in verif[:6]), raw={"txt": verif},
        ))
    return res


# ===========================================================================
# orchestration
# ===========================================================================
CATALOG = [
    {"name": "email_profile", "title": "بنية البريد و DNS", "accepts": ["email"]},
    {"name": "gravatar", "title": "Gravatar", "accepts": ["email"]},
    {"name": "breaches", "title": "التسريبات", "accepts": ["email"]},
    {"name": "domain_infra", "title": "بنية النطاق", "accepts": ["domain"]},
    {"name": "phone_profile", "title": "تحليل رقم الهاتف", "accepts": ["phone"]},
]


def detect_type(target: str) -> str:
    t = target.strip()
    if EMAIL_RE.match(t):
        return "email"
    if PHONE_RE.match(t.replace(" ", "")):
        return "phone"
    if DOMAIN_RE.match(t):
        return "domain"
    return "username"


async def timed(coro, module: str) -> Result:
    started = time.perf_counter()
    try:
        res = await coro
    except Exception as exc:  # noqa: BLE001 - one bad module must not fail the scan
        res = Result(module, status="error", error=f"{type(exc).__name__}: {exc}")
    res.duration = round(time.perf_counter() - started, 2)
    return res


async def scan(target: str, ttype: str, pivot: bool, region: str | None) -> dict[str, Any]:
    started = time.time()
    entities: dict[str, Entity] = {}
    edges: dict[str, Edge] = {}
    findings: list[Finding] = []
    reports: list[dict[str, Any]] = []
    log: list[dict[str, Any]] = []

    def note(msg: str, level: str = "info") -> None:
        log.append({"t": round(time.time() - started, 2), "level": level, "msg": msg})

    def absorb(res: Result) -> None:
        for e in res.entities:
            prev = entities.get(e.id)
            if prev is None:
                entities[e.id] = e
            else:
                # "input" is where the target came from, not a source that
                # independently confirms it - exclude it from corroboration.
                srcs = sorted({s for s in (prev.source, e.source) if s and s != "input"})
                if e.confidence > prev.confidence:
                    e.meta = {**prev.meta, **e.meta}
                    entities[e.id] = e
                else:
                    prev.meta.update(e.meta)
                merged = sorted((set(srcs) | set(entities[e.id].meta.get("sources", [])))
                                - {"input"})
                entities[e.id].meta["sources"] = merged
                entities[e.id].meta["corroboration"] = max(1, len(merged))
        for x in res.edges:
            key = f"{x.source}->{x.target}:{x.relation}"
            if key not in edges or x.confidence > edges[key].confidence:
                edges[key] = x
        findings.extend(res.findings)
        reports.append({
            "module": res.module, "status": res.status, "error": res.error,
            "note": res.note, "duration": res.duration,
            "counts": {"entities": len(res.entities), "findings": len(res.findings)},
        })
        note(f"{res.module}: {res.status} ({len(res.findings)} نتيجة) في {res.duration}ث",
             "warn" if res.status == "error" else "info")

    seed = Entity(ttype, target.strip(), source="input", meta={"seed": True})
    entities[seed.id] = seed
    note(f"بدء الفحص على {target} كنوع {ttype}")

    limits = httpx.Limits(max_connections=12)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True,
                                 limits=limits, headers={"User-Agent": USER_AGENT}) as client:
        # wave 1
        if ttype == "email":
            wave = [timed(mod_email_profile(client, target), "email_profile"),
                    timed(mod_gravatar(client, target), "gravatar"),
                    timed(mod_breaches(client, target), "breaches")]
        elif ttype == "domain":
            wave = [timed(mod_domain(client, target), "domain_infra")]
        elif ttype == "phone":
            wave = [timed(mod_phone(client, target, region), "phone_profile")]
        else:
            note("النسخة المخفّفة لا تدعم اسم المستخدم كمدخل — holehe و maigret غير متاحين هنا", "warn")
            wave = []

        for res in await asyncio.gather(*wave):
            absorb(res)

        # wave 2 — pivot onto anything cheap we just learned
        if pivot and (time.time() - started) < SCAN_BUDGET:
            targets = [
                e for e in list(entities.values())
                if e.type == "domain" and not e.meta.get("seed") and e.confidence >= CONF_DERIVED
            ][:2]
            if targets:
                note("محاور جديدة: " + "، ".join(f"{e.type}={e.value}" for e in targets))
                for res in await asyncio.gather(
                    *(timed(mod_domain(client, e.value), "domain_infra") for e in targets)
                ):
                    absorb(res)

    note(f"اكتمل الفحص في {time.time() - started:.1f} ثانية")

    ent_list = list(entities.values())
    edge_list = list(edges.values())
    return {
        "target": target, "target_type": ttype,
        "elapsed": round(time.time() - started, 2),
        "entities": [asdict(e) for e in ent_list],
        "edges": [asdict(x) for x in edge_list],
        "findings": [asdict(f) for f in findings],
        "modules": reports,
        "log": log,
        "graph": build_graph(ent_list, edge_list, seed.id),
        "summary": summarise(ent_list, findings, target, ttype),
    }


TYPE_LABELS = {
    "email": "بريد", "username": "اسم مستخدم", "phone": "هاتف", "domain": "نطاق",
    "person": "اسم", "account": "حساب", "breach": "تسريب", "image": "صورة",
    "url": "رابط", "location": "موقع",
}


def build_graph(entities: list[Entity], edges: list[Edge], seed_id: str) -> dict[str, Any]:
    known = {e.id for e in entities}
    nodes = []
    for e in entities:
        degree = sum(1 for x in edges if x.source == e.id or x.target == e.id)
        label = e.label if len(e.label) <= 32 else e.label[:31] + "…"
        nodes.append({"data": {
            "id": e.id, "label": label, "full": e.value, "type": e.type,
            "typeLabel": TYPE_LABELS.get(e.type, e.type),
            "confidence": round(e.confidence, 2), "source": e.source, "url": e.url,
            "seed": e.id == seed_id, "degree": degree,
            "corroboration": e.meta.get("corroboration", 1),
        }})
    links = [{"data": {
        "id": f"{x.source}->{x.target}:{x.relation}", "source": x.source, "target": x.target,
        "label": x.relation, "confidence": round(x.confidence, 2), "module": x.module,
    }} for x in edges if x.source in known and x.target in known]
    return {"nodes": nodes, "edges": links, "seed": seed_id}


def summarise(entities: list[Entity], findings: list[Finding],
              target: str, ttype: str) -> dict[str, Any]:
    by_type: dict[str, list[Entity]] = {}
    for e in entities:
        by_type.setdefault(e.type, []).append(e)
    accounts = by_type.get("account", [])
    breaches = by_type.get("breach", [])
    names = by_type.get("person", [])
    high = [f for f in findings if f.severity == "high"]
    corroborated = [e for e in entities if e.meta.get("corroboration", 0) > 1]

    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

    return {
        "target": target, "target_type": ttype,
        "counts": {
            "entities": len(entities), "findings": len(findings),
            "accounts": len(accounts), "breaches": len(breaches), "names": len(names),
            "high_severity": len(high), "corroborated": len(corroborated),
        },
        "by_category": by_cat,
        "exposure_score": min(100, len(breaches) * 12 + len(high) * 6
                              + len(accounts) * 2 + len(names) * 5),
        "names": sorted({e.value for e in names}),
        "breaches": sorted({e.value for e in breaches}),
    }


# ===========================================================================
# HTTP
# ===========================================================================
app = FastAPI(title="OSINT Suite Lite", version="1.0", docs_url="/api/docs")


class ScanRequest(BaseModel):
    target: str = Field(min_length=2, max_length=320)
    target_type: Literal["auto", "email", "phone", "domain"] = "auto"
    pivot: bool = True
    region: str | None = None


@app.get("/api/modules")
async def api_modules() -> dict[str, Any]:
    return {
        "modules": CATALOG,
        "edition": "lite",
        "unavailable": [
            {"name": "holehe", "reason": "يحتاج subprocess ودقائق من التنفيذ"},
            {"name": "maigret", "reason": "يحتاج subprocess ويتجاوز حدّ حجم الحزمة"},
            {"name": "ghunt", "reason": "يحتاج جلسة Google مخزّنة على القرص"},
        ],
    }


@app.post("/api/scan")
async def api_scan(req: ScanRequest) -> dict[str, Any]:
    target = req.target.strip()
    ttype = req.target_type if req.target_type != "auto" else detect_type(target)
    if ttype == "username":
        raise HTTPException(
            422,
            "النسخة المخفّفة على Vercel لا تدعم البحث باسم المستخدم — "
            "الوحدات المسؤولة (holehe و maigret) تحتاج تشغيل عمليات فرعية. "
            "استخدم نسخة Docker لهذا.",
        )
    try:
        return await asyncio.wait_for(
            scan(target, ttype, req.pivot, req.region), timeout=SCAN_BUDGET
        )
    except asyncio.TimeoutError:
        raise HTTPException(504, "تجاوز الفحص المهلة المسموحة على Vercel") from None


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True, "edition": "lite", "hibp": bool(HIBP_API_KEY)})
