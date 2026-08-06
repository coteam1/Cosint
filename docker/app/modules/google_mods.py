"""Google account discovery (GHunt) and domain infrastructure."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..config import GHUNT_CREDS, MODULE_TIMEOUT, TOOLS
from ..schemas import (
    CONF_CONFIRMED, CONF_STRONG, Edge, Entity, Finding, ModuleResult, make_id,
)
from .base import Module, register, run_cli


@register
class GHunt(Module):
    name = "ghunt"
    title = "GHunt — حساب Google"
    accepts = {"email"}
    category = "google"
    description = "معرّف Gaia، الصورة، مراجعات الخرائط، التقويم العام"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        binary = TOOLS.get("ghunt")
        if not binary:
            res.status = "not_configured"
            res.note = "GHunt غير مثبّت — pip install ghunt"
            return res
        if not Path(GHUNT_CREDS).exists():
            res.status = "not_configured"
            res.note = "GHunt يحتاج تسجيل دخول مرة واحدة: ghunt login"
            return res

        email = target.strip().lower()
        email_id = make_id("email", email)

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "ghunt.json"
            argv = [binary, "email", email, "--json", str(out_path)]
            try:
                code, out, err = await run_cli(argv, timeout=MODULE_TIMEOUT, cwd=tmp)
            except Exception as exc:  # noqa: BLE001
                res.status = "error"
                res.error = str(exc)[:300]
                return res
            data: dict[str, Any] = {}
            if out_path.exists():
                try:
                    data = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))
                except json.JSONDecodeError:
                    data = {}
            if not data:
                if "not found" in (out + err).lower():
                    res.note = "لا يوجد حساب Google مرتبط بهذا البريد"
                    return res
                res.status = "error"
                res.error = (err or out).strip()[:300] or "لم يُنتج GHunt مخرجات"
                return res

        prof = data.get("PROFILE_CONTAINER", {}).get("profile", data)
        gaia = prof.get("gaiaId") or data.get("gaiaId")
        name = prof.get("name") or prof.get("fullName")
        pic = (prof.get("profilePhotos") or {}).get("PROFILE", {}).get("url") \
            or prof.get("profilePicture")

        if gaia:
            g = Entity(type="gaia_id", value=str(gaia), source=self.name, confidence=CONF_CONFIRMED,
                       url=f"https://www.google.com/maps/contrib/{gaia}/reviews")
            res.entities.append(g)
            res.edges.append(Edge(email_id, g.id, "google_account", CONF_CONFIRMED, self.name))
            res.findings.append(Finding(
                module=self.name, category="google", title=f"معرّف Gaia: {gaia}",
                detail="يمكن استخدامه للوصول لمراجعات خرائط Google العامة",
                url=g.url, severity="notable",
            ))
        if name:
            p = Entity(type="person", value=str(name), source=self.name, confidence=CONF_STRONG)
            res.entities.append(p)
            res.edges.append(Edge(email_id, p.id, "identifies_as", CONF_STRONG, self.name))
            res.findings.append(Finding(self.name, "google", f"اسم حساب Google: {name}",
                                        confidence=CONF_STRONG, severity="notable"))
        if pic:
            img = Entity(type="image", value=str(pic), label="صورة حساب Google",
                         source=self.name, confidence=CONF_CONFIRMED, url=str(pic))
            res.entities.append(img)
            res.edges.append(Edge(email_id, img.id, "has_avatar", CONF_CONFIRMED, self.name))
            res.findings.append(Finding(self.name, "google", "صورة الحساب متاحة", url=str(pic)))

        for key, label in (("MAPS", "مراجعات الخرائط"), ("CALENDAR", "التقويم العام"),
                           ("PLAY_GAMES", "ملف Play Games")):
            block = data.get(f"{key}_CONTAINER") or data.get(key)
            if block:
                res.findings.append(Finding(
                    self.name, "google", f"{label}: بيانات عامة متاحة",
                    detail=json.dumps(block, ensure_ascii=False)[:300], raw={"key": key},
                ))
        return res


@register
class DomainInfra(Module):
    name = "domain_infra"
    title = "بنية النطاق"
    accepts = {"domain"}
    category = "infra"
    description = "سجلات A/NS/TXT، SPF و DMARC"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        try:
            import dns.asyncresolver
        except ImportError:
            res.status = "not_configured"
            res.note = "pip install dnspython"
            return res

        domain = target.strip().lower().lstrip("@")
        did = make_id("domain", domain)

        async def q(name: str, rtype: str) -> list[str]:
            try:
                ans = await dns.asyncresolver.resolve(name, rtype)
                return [r.to_text().strip('"') for r in ans]
            except Exception:  # noqa: BLE001
                return []

        a_records = await q(domain, "A")
        ns_records = await q(domain, "NS")
        txt_records = await q(domain, "TXT")
        dmarc = await q(f"_dmarc.{domain}", "TXT")

        if a_records:
            res.findings.append(Finding(self.name, "infra", "عناوين IP", detail=" · ".join(a_records)))
            for ip in a_records[:5]:
                e = Entity(type="url", value=ip, label=f"IP {ip}", source=self.name, confidence=CONF_CONFIRMED)
                res.entities.append(e)
                res.edges.append(Edge(did, e.id, "resolves_to", CONF_CONFIRMED, self.name))
        if ns_records:
            res.findings.append(Finding(self.name, "infra", "خوادم الأسماء", detail=" · ".join(ns_records)))

        spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
        if spf:
            res.findings.append(Finding(self.name, "infra", "سجل SPF", detail=spf[0][:300]))
        else:
            res.findings.append(Finding(self.name, "infra", "لا يوجد سجل SPF",
                                        detail="النطاق عرضة لانتحال البريد", severity="notable"))
        if dmarc:
            policy = "none"
            for part in dmarc[0].split(";"):
                if part.strip().startswith("p="):
                    policy = part.split("=", 1)[1].strip()
            res.findings.append(Finding(
                self.name, "infra", f"سياسة DMARC: {policy}",
                severity="notable" if policy == "none" else "info", detail=dmarc[0][:300],
            ))
        else:
            res.findings.append(Finding(self.name, "infra", "لا يوجد سجل DMARC", severity="notable"))

        verifications = [t for t in txt_records if "verification" in t.lower() or "-site-" in t.lower()]
        if verifications:
            res.findings.append(Finding(
                self.name, "infra", "خدمات مُتحقَّق منها على النطاق",
                detail=" · ".join(v[:60] for v in verifications[:6]),
                raw={"txt": verifications},
            ))
        return res
