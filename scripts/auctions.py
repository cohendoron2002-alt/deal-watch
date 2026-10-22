#!/usr/bin/env python3
"""Deal Watch: Vienna auctions refresher.

Collects every Vienna real estate auction we can see in public sources:
  * court auctions from the Austrian Ediktsdatei (incl. results: Meistbot / Zuschlag)
  * agent bidding procedures (Bieterverfahren) advertised on willhaben

For each item it estimates a fair value from comparable willhaben listings
(same district, same property type, similar size) and works out what share of
that fair value the minimum bid, court valuation and winning bid are.

The result is encrypted with the site's public key (RSA-OAEP + AES-GCM) and
written to auctions.enc.json, so only someone with the site password can read it.

Usage: python3 auctions.py --out auctions.enc.json --pubkey scripts/auction_pub.pem
       [--state state/auction_state.json] [--plain debug.json]
"""
import argparse, base64, html, json, os, re, statistics, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from curl_cffi import requests

VIE = ZoneInfo("Europe/Vienna")
NOW = datetime.now(VIE)
EDI = "https://edikte.justiz.gv.at/edikte/ex/exedi3.nsf/"
WH = "https://www.willhaben.at/iad/"

DISTRICTS = {
    "1010": "innere-stadt", "1020": "leopoldstadt", "1030": "landstrasse", "1040": "wieden",
    "1050": "margareten", "1060": "mariahilf", "1070": "neubau", "1080": "josefstadt",
    "1090": "alsergrund", "1100": "favoriten", "1110": "simmering", "1120": "meidling",
    "1130": "hietzing", "1140": "penzing", "1150": "rudolfsheim-fuenfhaus", "1160": "ottakring",
    "1170": "hernals", "1180": "waehring", "1190": "doebling", "1200": "brigittenau",
    "1210": "floridsdorf", "1220": "donaustadt", "1230": "liesing",
}

# Ediktsdatei category -> comparable group
FLAT = {"Wohnungseigentumsobjekt", "Eigentumswohnung", "Maisonette", "Dachterrassenwohnung",
        "Dachgeschoßwohnung", "Garconniere", "Gartenwohnung"}
HOUSE = {"Einfamilienhaus", "Zweifamilienhaus", "Reihenhaus", "Mehrfamilienhaus"}
PLOT = {"unbebaute Liegenschaft", "bebaubare Liegenschaft"}
ZINS = {"Mietwohnhaus", "Mietshaus", "gemischt genutztes Haus"}
WH_CAT = {"flat": "eigentumswohnung", "house": "haus-kaufen", "plot": "grundstuecke"}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def get(url, tries=3, timeout=45):
    for i in range(tries):
        try:
            r = requests.get(url, impersonate="chrome", timeout=timeout)
            if r.status_code == 200:
                return r
            log("HTTP", r.status_code, url[:120])
        except Exception as e:  # noqa
            log("ERR", str(e)[:120], url[:120])
        time.sleep(2 + 3 * i)
    return None


def num(s):
    """'728.100,00 EUR' -> 728100.0"""
    if s is None:
        return None
    s = html.unescape(str(s)).replace("\xa0", " ")
    m = re.search(r"\d[\d.\s]*(?:,\d+)?", s)
    if not m:
        return None
    t = m.group(0).replace(" ", "").replace(".", "").replace(",", ".")
    try:
        return float(t)
    except ValueError:
        return None


def clean(s):
    s = re.sub(r"<br\s*/?>", "\n", s or "")
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s).replace("\xa0", " ")
    return re.sub(r"[ \t]+", " ", s).strip()


def parse_dt(s):
    """'am 20.10.2026 um 09:30 Uhr' -> aware datetime"""
    if not s:
        return None
    m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{2,4})(?:\D{1,12}(\d{1,2})[:.](\d{2}))?", s)
    if not m:
        return None
    d, mo, y, hh, mm = m.groups()
    y = int(y) + (2000 if len(y) == 2 else 0)
    try:
        return datetime(y, int(mo), int(d), int(hh or 0), int(mm or 0), tzinfo=VIE)
    except ValueError:
        return None


# --------------------------------------------------------------- Ediktsdatei
def edikte_list():
    url = EDI + "suchedi?SearchView&subf=eex&SearchOrder=4&SearchMax=4999&query=([BL]=(0))"
    r = get(url, timeout=90)
    if not r:
        raise SystemExit("Ediktsdatei list unavailable")
    rows = []
    for tr in re.findall(r'<tr><td class="zentriert".*?</tr>', r.text, re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        link = re.search(r'href="(alldoc/[^"!]+)', tr)
        if not link or len(tds) < 4:
            continue
        rows.append({"doc": link.group(1), "label": clean(tds[1]), "addr": clean(tds[2]), "obj": clean(tds[3])})
    return rows


def edikte_doc(doc):
    r = get(EDI + doc + "!OpenDocument")
    if not r:
        return None
    t = r.text
    f = {}
    for lab, val in re.findall(r'<span class="col-sm-3 text-right">([^<]+?):?</span>\s*<p class="col-sm-9">(.*?)</p>', t, re.S):
        lab = clean(lab).rstrip(":")
        if lab not in f:
            f[lab] = clean(val)
    title = clean((re.search(r"<h3[^>]*>(.*?)</h3>", t, re.S) or re.search(r"<title>(.*?)</title>", t, re.S) or [None, ""])[1])
    zus = re.search(r"um das Meistbot von\s*(?:<[^>]+>|\s)*([\d.,]+)", t)
    if zus:
        f["Meistbot"] = zus.group(1) + " EUR"
    photos = []
    for ph in re.findall(r'href="(/edikte/ex/exedi3\.nsf/[^"]+\$file/[^"]+\.(?:jpg|jpeg|png))"', t, re.I):
        if ph not in photos:
            photos.append(ph)
    # real photos first, site plans and floor plans last
    photos.sort(key=lambda u: 1 if re.search(r"lageplan|grundriss|plan|gr[_ ]?top|kataster|mappe", u, re.I) else 0)
    attach = re.findall(r'href="(/edikte/ex/exedi3\.nsf/[^"]+\$file/[^"]+\.pdf)"[^>]*>([^<]*)', t, re.I)
    f["_photos"] = ["https://edikte.justiz.gv.at" + p for p in photos[:8]]
    f["_pdfs"] = [{"url": "https://edikte.justiz.gv.at" + u, "name": clean(n)} for u, n in attach[:6]]
    f["_title"] = title
    f["_text"] = clean(t)[:20000]
    return f


PARKING = re.compile(r"kfz|pkw|stellplatz|abstellplatz|garage(?!nwohnung)|parkplatz", re.I)
COMMERCIAL = re.compile(r"büro|geschäft|lokal|lager|magazin|werkstätte|gewerb|ordination|hotel", re.I)
SHELL = re.compile(r"rohdachboden|dachboden|rohbau|dachgeschossausbau", re.I)


def group_of(cats, title=""):
    t = title or ""
    if PARKING.search(t):
        return "parking"
    if SHELL.search(t):
        return "shell"
    if COMMERCIAL.search(t) and not re.search(r"wohnung", t, re.I):
        return "commercial"
    cs = {c.strip() for c in re.split(r",|;", cats or "") if c.strip()}
    if cs & FLAT:
        return "flat"
    if cs & HOUSE:
        return "house"
    if cs & PLOT:
        return "plot"
    if cs & ZINS:
        return "zinshaus"
    return "other"


def court_items(state):
    rows = edikte_list()
    log("edikte rows", len(rows))
    with ThreadPoolExecutor(6) as ex:
        docs = list(ex.map(lambda r: edikte_doc(r["doc"]), rows))
    auctions, results = {}, []
    for row, f in zip(rows, docs):
        if not f:
            continue
        kind = re.sub(r"\s*\(.*", "", row["label"]).strip()
        case = f.get("Aktenzeichen", "")
        court = f.get("Dienststelle", "")
        key = re.sub(r"\s+", " ", f"{court}|{case}|{f.get('BLNr', '')}|{row['obj']}").strip()
        if kind in ("Versteigerung", "Verschiebung", "Entfall des Termins"):
            when = parse_dt(f.get("Versteigerungstermin") or f.get("Neuer Tagsatzungstermin") or f.get("Termin") or row["label"])
            plz = (re.search(r"\b(1\d\d0)\b", f.get("PLZ/Ort", "") + " " + row["addr"]) or [None, None])[1]
            it = {
                "id": "edi-" + row["doc"].split("/")[-1],
                "kind": "court",
                "status": {"Versteigerung": "upcoming", "Verschiebung": "postponed", "Entfall des Termins": "cancelled"}[kind],
                "title": f"{row['obj'] or f.get('_title', '')}".strip(),
                "address": f.get("Liegenschaftsadresse") or row["addr"],
                "postcode": plz,
                "district": DISTRICTS.get(plz or "", "").replace("-", " ").title() or None,
                "category": f.get("Kategorie(n)"),
                "group": group_of(f.get("Kategorie(n)"), row["obj"]),
                "size_m2": num(f.get("Objektgröße")),
                "plot_m2": num(f.get("Grundstücksgröße")),
                "court": court, "case_no": case,
                "reason": f.get("wegen"),
                "starts_at": when.isoformat() if when else None,
                "place": f.get("Versteigerungsort") or f.get("Neuer Ort") or f.get("Ort"),
                "viewing": f.get("Besichtigungszeit"),
                "valuation": num(f.get("Schätzwert")),
                "min_bid": num(f.get("Geringstes Gebot")),
                "deposit": num(f.get("Vadium")),
                "description": (f.get("Beschreibung (WE)") or f.get("Beschreibung") or "")[:600],
                "notes": (f.get("Sonstige Hinweise") or "")[:400],
                "photos": f["_photos"], "pdfs": f["_pdfs"],
                "url": EDI + row["doc"] + "!OpenDocument",
                "key": key,
            }
            if f.get("Meistbot"):
                # a postponed distribution hearing: the auction itself already happened
                it["highest_bid"] = num(f["Meistbot"])
                it["highest_bid_note"] = "Winning bid (Meistbot) published by the court"
                it["status"] = "sold"
                it["result_url"] = it["url"]
                it["result_date"] = (parse_dt(f.get("Letzte Änderung am") or f.get("Bekannt gemacht am")) or NOW).isoformat()
            auctions[key] = it
        elif kind in ("Zuschlag ohne Überbot", "Zuschlag", "Meistbotsverteilung", "Überbot", "Zuschlag mit Überbot"):
            results.append({"key": key, "court": court, "case_no": case, "kind": kind,
                            "meistbot": num(f.get("Meistbot")),
                            "date": (parse_dt(f.get("Bekannt gemacht am")) or NOW).isoformat(),
                            "address": f.get("Liegenschaftsadresse") or row["addr"], "obj": row["obj"],
                            "url": EDI + row["doc"] + "!OpenDocument"})
    # merge previous state so finished auctions keep their details
    prev = {i["key"]: i for i in state.get("court", []) if i.get("key")}
    for k, it in prev.items():
        if k not in auctions:
            it = dict(it)
            if it.get("status") == "upcoming" and it.get("starts_at") and datetime.fromisoformat(it["starts_at"]) < NOW:
                it["status"] = "held"
            auctions[k] = it
    # attach results by court + case (+ BLNr when it matches)
    for res in results:
        norm = lambda x: re.sub(r"[^a-z0-9]", "", (x or "").lower())
        same = [a for a in auctions.values() if a["court"] == res["court"] and a["case_no"] == res["case_no"]]
        cand = [a for a in same if norm(a.get("title")) == norm(res["obj"])] or (same if len(same) == 1 else [])
        if not cand:
            plz = (re.search(r"\b(1\d\d0)\b", res["address"] or "") or [None, None])[1]
            cand = [{
                "id": "edi-res-" + res["url"].split("/")[-1].split("!")[0], "kind": "court", "status": "sold",
                "title": res["obj"] or "Court auction result", "address": res["address"], "postcode": plz,
                "district": DISTRICTS.get(plz or "", "").replace("-", " ").title() or None,
                "group": group_of("", res["obj"]) if group_of("", res["obj"]) != "other" else ("flat" if re.search(r"wohnung|top|\bw ?\d", res["obj"] or "", re.I) else "other"),
                "court": res["court"], "case_no": res["case_no"], "url": res["url"], "key": res["key"],
                "photos": [], "pdfs": []}]
            auctions[res["key"]] = cand[0]
        for a in cand:
            if res["meistbot"] and not (a.get("status") == "sold" and a.get("highest_bid")):
                a["highest_bid"] = res["meistbot"]
                a["highest_bid_note"] = "Winning bid (Meistbot) published by the court"
                a["status"] = "sold"
                a["result_url"] = res["url"]
                a["result_date"] = res["date"]
    out = []
    for a in auctions.values():
        if a.get("status") == "upcoming" and a.get("starts_at") and datetime.fromisoformat(a["starts_at"]) < NOW - timedelta(hours=3):
            a["status"] = "held"
        # drop finished items older than 60 days
        ref = a.get("result_date") or a.get("starts_at")
        if a.get("status") in ("held", "sold", "cancelled") and ref and datetime.fromisoformat(ref) < NOW - timedelta(days=60):
            continue
        if a.get("status") in ("upcoming", "postponed") and not a.get("highest_bid"):
            a["highest_bid_note"] = "Not public: bids are made live in the courtroom"
        out.append(a)
    log("court items", len(out), "results", len(results))
    return out


# --------------------------------------------------------------- willhaben
def wh_search(url):
    r = get(url)
    if not r:
        return None, []
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.S)
    if not m:
        return None, []
    sr = (json.loads(m.group(1))["props"]["pageProps"].get("searchResult") or {})
    ads = (sr.get("advertSummaryList") or {}).get("advertSummary") or []
    res = []
    for a in ads:
        at = {x["name"]: x["values"][0] for x in (a.get("attributes") or {}).get("attribute", []) if x.get("values")}
        res.append({"id": a.get("id"), "title": a.get("description"), "body": at.get("BODY_DYN") or "", "price": num(at.get("PRICE")),
                    "living": num(at.get("ESTATE_SIZE/LIVING_AREA") or at.get("ESTATE_SIZE")),
                    "plot": num(at.get("PLOT/AREA") or at.get("ESTATE_SIZE")), "postcode": at.get("POSTCODE"),
                    "location": at.get("LOCATION"), "seo": at.get("SEO_URL"), "rooms": at.get("NUMBER_OF_ROOMS")})
    return sr.get("rowsFound"), res


_comp_cache = {}
_wh_ok = {"ok": 0, "fail": 0}


NEWBUILD = re.compile(r"erstbezug|neubauprojekt|neubau|fertigstellung|bauträger|baubeginn|übergabe 202|projekt", re.I)


def comps(group, plz, size, new=False):
    if group not in WH_CAT or not plz or plz not in DISTRICTS or not size:
        return None
    cat = WH_CAT[group]
    area = f"wien/wien-{plz}-{DISTRICTS[plz]}"
    field = "PLOT/AREA" if group == "plot" else "ESTATE_SIZE/LIVING_AREA"
    for spread in (0.3, 0.5, None):
        q = f"{WH}immobilien/{cat}/{area}?rows=90"
        if spread:
            lo, hi = int(size * (1 - spread)), int(size * (1 + spread)) + 1
            q += f"&{field}_FROM={lo}&{field}_TO={hi}"
        if q in _comp_cache:
            n, rows = _comp_cache[q]
        else:
            n, rows = wh_search(q)
            _comp_cache[q] = (n, rows)
            _wh_ok["ok" if n is not None else "fail"] += 1
            time.sleep(0.4)
        if n is None:
            return None
        vals = []
        for r in rows:
            sz = r["plot"] if group == "plot" else r["living"]
            if not r["price"] or not sz or sz < 10 or r["price"] < 20000:
                continue
            if r.get("postcode") and r["postcode"] != plz:
                continue
            if re.search(r"bieterverfahren|versteigerung|auktion|mindestgebot", (r["title"] or "").lower()):
                continue
            if group == "flat" and not new and NEWBUILD.search((r["title"] or "") + " " + r["body"]):
                continue
            vals.append(r["price"] / sz)
        if len(vals) >= 6:
            vals.sort()
            k = len(vals) // 10  # trim top and bottom 10%
            core = vals[k:len(vals) - k] if len(vals) > 10 else vals
            med = statistics.median(core)
            label = {"flat": "existing flats" if not new else "new-build flats", "house": "houses", "plot": "building plots"}[group]
            return {"m2": round(med), "n": len(vals), "url": q.replace("?rows=90&", "?").replace("?rows=90", ""),
                    "basis": f"median asking price of {len(vals)} {label} for sale in {plz}"
                             + (f", {int(size*(1-spread))}-{int(size*(1+spread))} m²" if spread else ", all sizes")}
    return None


KW = r"bieterverfahren|bietverfahren|angebotsverfahren|mindestgebot|startpreis|ausrufpreis|sofortkaufpreis|versteigerung|auktion|gebote ab|bestbieter"


def wh_detail(seo):
    r = get(WH + seo)
    if not r:
        return None
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', r.text, re.S)
    if not m:
        return {"expired": True}
    ad = json.loads(m.group(1))["props"]["pageProps"].get("advertDetails") or {}
    at = {x["name"]: x["values"] for x in (ad.get("attributes") or {}).get("attribute", [])}
    g = lambda k: (at.get(k) or [None])[0]
    desc = " ".join(v[0] for k, v in at.items() if k == "DESCRIPTION" or k.startswith("GENERAL_TEXT_ADVERT"))
    desc = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", desc)))
    return {"desc": desc, "addr": g("LOCATION/ADDRESS_1"), "postcode": g("LOCATION/POSTCODE") or g("POSTCODE"),
            "org": g("CONTACT/COMPANY") or ("Private seller" if g("ISPRIVATE") == "1" else None),
            "living": num(g("ESTATE_SIZE/LIVING_AREA")), "plot": num(g("PLOT/AREA") or g("FREE_AREA/FREE_AREA_AREA_TOTAL")),
            "title": ad.get("description")}


def money_after(text, labels):
    m = re.search(r"(?:" + labels + r")[^0-9€]{0,40}(?:EUR|€)?\s*([\d][\d.\s]*(?:,\d+)?)\s*(Mio)?", text, re.I)
    if not m:
        return None
    v = num(m.group(1))
    if v and m.group(2):
        v *= 1_000_000
    if v and v < 1000:
        v *= 1000 if v < 100 else 1
    return v if v and v >= 20000 else None


def deadline(text):
    best = None
    for m in re.finditer(r"(frist|bis zum|bis|endet|ende|abgabe|gebotsabgabe|bietphase|bieterverfahren läuft|läuft)[^.]{0,80}?(\d{1,2}\.\s?\d{1,2}\.\s?\d{2,4})(?:[^0-9]{1,15}(\d{1,2})[:.](\d{2}))?", text, re.I):
        d = parse_dt(m.group(2).replace(" ", "") + (f" {m.group(3)}:{m.group(4)}" if m.group(3) else ""))
        if d and d > NOW - timedelta(days=1) and d < NOW + timedelta(days=365):
            if m.group(3) is None:
                d = d.replace(hour=23, minute=59)
            if best is None or d < best:
                best = d
    return best


def agent_items(court):
    seen = {}
    words = ["bieterverfahren", "bietverfahren", "angebotsverfahren", "mindestgebot", "höchstgebot", "versteigerung", "auktion", "startpreis", "sofortkaufpreis"]
    for kw in words:
        for cat in ("eigentumswohnung", "haus-kaufen", "grundstuecke"):
            n, rows = wh_search(f"{WH}immobilien/{cat}/wien?keyword={kw}&rows=200")
            for r in rows:
                if r["id"] not in seen:
                    r["cat"] = cat
                    seen[r["id"]] = r
            time.sleep(0.3)
    log("agent candidates", len(seen))
    rows = list(seen.values())
    with ThreadPoolExecutor(5) as ex:
        dets = list(ex.map(lambda r: wh_detail(r["seo"]) if r.get("seo") else None, rows))
    out = []
    for r, d in zip(rows, dets):
        if not d or d.get("expired"):
            continue
        text = d["desc"]
        low = text.lower()
        if not re.search(KW, low) or "höchstgebot gewährleistet" in low and not re.search(r"bieterverfahren|mindestgebot", low):
            continue
        group = {"eigentumswohnung": "flat", "haus-kaufen": "house", "grundstuecke": "plot"}[r["cat"]]
        plz = d.get("postcode") or r.get("postcode")
        size = r["plot"] if group == "plot" else (d.get("living") or r["living"])
        start = money_after(text, r"startpreis|mindestgebot|mindestangebot|ausrufpreis|gebote? ab|kaufpreis ab|gegen gebot ab|richtpreis") or r["price"]
        buy = money_after(text, r"sofortkaufpreis|sofortkauf")
        ends = deadline(text)
        court_ref = bool(re.search(r"edikte\.justiz|gerichtlich|352b|bezirksgericht", low))
        it = {
            "id": f"wh-{r['id']}", "kind": "agent", "status": "open",
            "title": d.get("title") or r["title"], "address": d.get("addr") or r.get("location"),
            "postcode": plz, "district": DISTRICTS.get(plz or "", "").replace("-", " ").title() or None,
            "group": group, "size_m2": size if group != "plot" else None, "plot_m2": r["plot"] if group == "plot" else d.get("plot"),
            "seller": d.get("org"), "start_price": start, "buy_now": buy,
            "ends_at": ends.isoformat() if ends else None,
            "highest_bid_note": "Not public: offers go privately to the agent" if not re.search(r"dave|digital", low)
                                else "Visible only to registered bidders on the agent's bidding platform",
            "description": text[:600], "url": WH + r["seo"], "court_ref": court_ref, "photos": [], "pdfs": [],
        }
        # merge with a matching court auction instead of listing it twice
        # (closest plot or living area within 2% in the same district; never a different property type)
        twin = None
        if court_ref:
            best = None
            for c in court:
                if c.get("postcode") != plz or c.get("status") not in ("upcoming", "postponed"):
                    continue
                if (group == "plot") != (c.get("group") == "plot"):
                    continue
                cs = c.get("plot_m2") if group == "plot" else c.get("size_m2")
                if not cs or not size:
                    continue
                gap = abs(cs - size) / size
                if gap <= 0.02 and (best is None or gap < best[0]):
                    best = (gap, c)
            twin = best[1] if best else None
        if twin:
            twin["url2"] = it["url"]
            twin["agent_note"] = f"Also advertised by {it['seller'] or 'an agent'} on willhaben"
            if ends and not twin.get("ends_at"):
                twin["ends_at"] = it["ends_at"]
            continue
        if ends and ends < NOW:
            continue
        out.append(it)
    log("agent items", len(out))
    return out


# --------------------------------------------------------------- valuation
def value(it):
    if it["group"] == "plot":
        size = it.get("plot_m2")
    elif it["group"] == "house":
        size = it.get("size_m2") or it.get("plot_m2")
    elif it["group"] == "flat":
        size = it.get("size_m2")
    else:
        size = None
    new = bool(NEWBUILD.search((it.get("title") or "") + " " + (it.get("description") or "")[:300])) and it["kind"] == "agent"
    c = comps(it["group"], it.get("postcode"), size, new) if size else None
    if c:
        it["fair_m2"] = c["m2"]
        it["fair_value"] = round(c["m2"] * size, -3)
        it["fair_basis"] = c["basis"]
        it["comps_url"] = c["url"]
        it["comps_n"] = c["n"]
    elif it.get("valuation"):
        it["fair_value"] = it["valuation"]
        it["fair_basis"] = ("court valuation (no reliable comparables for this type)" if it["group"] not in ("flat", "house", "plot")
                            else "court valuation (not enough comparable listings)")
    fv = it.get("fair_value")
    if fv:
        for k, src in (("pct_min", "min_bid"), ("pct_valuation", "valuation"), ("pct_highest", "highest_bid"),
                       ("pct_start", "start_price"), ("pct_buy_now", "buy_now")):
            if it.get(src):
                it[k] = round(it[src] / fv * 100)
    if size and it.get("highest_bid"):
        it["highest_m2"] = round(it["highest_bid"] / size)
    flags = []
    if it["group"] in ("parking", "commercial", "shell", "zinshaus", "other") and it["kind"] == "court":
        flags.append({"parking": "Parking space", "commercial": "Commercial unit, not a home", "shell": "Unfinished attic or shell, needs building work",
                      "zinshaus": "Whole rental building", "other": "Special case (share, Baurecht or other right)"}[it["group"]])
    if it.get("valuation") and it.get("fair_value") and it.get("comps_n") and it["valuation"] / it["fair_value"] < 0.55:
        flags.append("Court valuation is far below market: usually means it is rented out, only a share, or in poor shape. Read the valuation report.")
    if re.search(r"anteil|miteigentum", (it.get("reason") or "") + " " + (it.get("title") or ""), re.I):
        flags.append("Only a share of the property is being sold")
    if re.search(r"baurecht|superädifikat", (it.get("title") or "") + " " + (it.get("category") or ""), re.I):
        flags.append("Building right (Baurecht), not freehold land")
    if re.search(r"vermietet|bestandsvertrag|mietvertrag|mieter", (it.get("description") or "") + " " + (it.get("notes") or ""), re.I):
        flags.append("Mentions a tenant or lease")
    it["flags"] = flags
    return it


# --------------------------------------------------------------- encryption
def encrypt(payload, pub_pem):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pub = serialization.load_pem_public_key(pub_pem)
    key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode(), None)
    ek = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "updated": payload["updated"], "k": b(ek), "iv": b(iv), "ct": b(ct)}


GEO = {}


def geocode(addr, plz):
    """OpenStreetMap Nominatim lookup (max 1 request per second), cached across runs in the state file."""
    if not addr:
        return None
    a = re.split(r" ident |/| und |;", addr)[0].strip()
    q = f"{a}, {plz or ''} Wien".strip() if plz and plz.startswith("1") else a
    if q in GEO:
        return GEO[q]
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search", params={"format": "json", "limit": 1, "countrycodes": "at", "q": q},
                         headers={"User-Agent": "deal-watch-tracker/1.0 (private, low volume)"}, timeout=30)
        js = r.json() if r.status_code == 200 else []
        GEO[q] = [float(js[0]["lat"]), float(js[0]["lon"])] if js else None
    except Exception:
        GEO[q] = None
    time.sleep(1.1)
    return GEO[q]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--state", default=None)
    ap.add_argument("--plain", default=None)
    a = ap.parse_args()
    state = {}
    if a.state and os.path.exists(a.state):
        try:
            state = json.load(open(a.state))
        except Exception:
            state = {}
    GEO.update(state.get("geo") or {})
    court = court_items(state)
    try:
        agent = agent_items(court)
    except Exception as e:  # never lose the court data because of willhaben
        log("agent scan failed", e)
        agent = state.get("agent", [])
    for it in court + agent:
        try:
            if it.get("status") in ("upcoming", "postponed", "open") and not it.get("lat"):
                ll = geocode(it.get("address"), it.get("postcode"))
                if ll:
                    it["lat"], it["lng"] = ll
        except Exception as e:
            log("geocode failed", it.get("id"), e)
        try:
            value(it)
        except Exception as e:
            log("value failed", it.get("id"), e)
    payload = {"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "sources": {"court": len(court), "agent": len(agent), "willhaben_ok": _wh_ok["ok"], "willhaben_fail": _wh_ok["fail"]},
               "items": court + agent}
    if a.state:
        os.makedirs(os.path.dirname(a.state) or ".", exist_ok=True)
        json.dump({"court": court, "agent": agent, "geo": GEO}, open(a.state, "w"), ensure_ascii=False)
    if a.plain:
        json.dump(payload, open(a.plain, "w"), ensure_ascii=False, indent=1)
    enc = encrypt(payload, open(a.pubkey, "rb").read())
    json.dump(enc, open(a.out, "w"))
    log("wrote", a.out, "items", len(payload["items"]), payload["sources"])


if __name__ == "__main__":
    main()
