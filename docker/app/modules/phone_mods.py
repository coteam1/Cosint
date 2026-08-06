"""Phone-seeded modules. Fully offline by default."""
from __future__ import annotations

from typing import Any

from ..config import NUMVERIFY_KEY
from ..schemas import (
    CONF_CONFIRMED, Edge, Entity, Finding, ModuleResult, make_id,
)
from .base import Module, http_client, register, safe_json

LINE_TYPES = {
    0: "خط أرضي", 1: "جوال", 2: "أرضي أو جوال", 3: "رقم مجاني",
    4: "رقم مدفوع", 5: "تكلفة مشتركة", 6: "VoIP", 7: "رقم شخصي",
    8: "نداء آلي", 9: "UAN", 10: "غير معروف", 27: "بريد صوتي",
}


@register
class PhoneProfile(Module):
    name = "phone_profile"
    title = "تحليل رقم الهاتف"
    accepts = {"phone"}
    category = "phone"
    description = "الدولة، المشغّل، نوع الخط والمناطق الزمنية — بدون اتصال بالإنترنت"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
        except ImportError:
            res.status = "not_configured"
            res.note = "pip install phonenumbers"
            return res

        raw = target.strip()
        region_hint = ctx.get("region")
        try:
            num = phonenumbers.parse(raw, region_hint)
        except phonenumbers.NumberParseException as exc:
            res.status = "error"
            res.error = f"تعذّر تحليل الرقم: {exc}"
            return res

        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        pid = make_id("phone", e164)
        valid = phonenumbers.is_valid_number(num)
        possible = phonenumbers.is_possible_number(num)

        country = geocoder.description_for_number(num, "ar") or geocoder.description_for_number(num, "en")
        net = carrier.name_for_number(num, "en")
        zones = list(timezone.time_zones_for_number(num))
        ltype = LINE_TYPES.get(phonenumbers.number_type(num), "غير معروف")

        res.entities.append(Entity(
            type="phone", value=e164, source=self.name, confidence=CONF_CONFIRMED,
            meta={"valid": valid, "carrier": net, "region": country},
        ))

        res.findings.append(Finding(
            module=self.name, category="phone",
            title=f"الرقم {'صالح' if valid else 'غير صالح'} — {e164}",
            detail=f"دولي: {phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}",
            severity="info" if valid else "notable",
            raw={"valid": valid, "possible": possible},
        ))
        if country:
            res.findings.append(Finding(self.name, "phone", f"المنطقة: {country}"))
        if net:
            res.findings.append(Finding(self.name, "phone", f"المشغّل عند الإصدار: {net}",
                                        detail="قد يتغيّر مع نقل الرقم بين الشبكات"))
        res.findings.append(Finding(self.name, "phone", f"نوع الخط: {ltype}"))
        if zones:
            res.findings.append(Finding(self.name, "phone", "المناطق الزمنية: " + "، ".join(zones)))
            for z in zones[:3]:
                loc = Entity(type="location", value=z, source=self.name, confidence=0.6)
                res.entities.append(loc)
                res.edges.append(Edge(pid, loc.id, "timezone", 0.6, self.name))

        if NUMVERIFY_KEY:
            try:
                async with http_client() as client:
                    r = await client.get("http://apilayer.net/api/validate", params={
                        "access_key": NUMVERIFY_KEY, "number": e164.lstrip("+"),
                    })
                data = safe_json(r.text) or {}
                if data.get("valid"):
                    res.findings.append(Finding(
                        self.name, "phone", "تأكيد Numverify",
                        detail=f"{data.get('carrier','')} · {data.get('location','')} · {data.get('line_type','')}",
                        raw=data,
                    ))
            except Exception as exc:  # noqa: BLE001
                res.note += f"Numverify: {exc}"

        return res
