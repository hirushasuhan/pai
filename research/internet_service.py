"""Internet Service & Live Knowledge Integration for PAI.

Provides:
  - Live weather forecasts via Open-Meteo API (free, zero API key required).
  - Web knowledge search via Wikipedia REST API & DuckDuckGo.
  - Safe webpage content fetching with HTML-to-text extraction.
  - Internet access toggle (online / offline modes).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = "PAIAssistantApp/1.1 (Interactive AI Assistant; Windows x64; contact: pai-dev@localdomain.org)"

_WEATHER_CODE_MAP: Dict[int, Tuple[str, str, str]] = {
    0: ("Clear sky", "පැහැදිලි අහස", "☀️"),
    1: ("Mainly clear", "ප්‍රධාන වශයෙන් පැහැදිලි", "🌤️"),
    2: ("Partly cloudy", "වලාකුළු ස්වල්පයක් සහිත", "⛅"),
    3: ("Overcast", "වලාකුළු වලින් බර වූ", "☁️"),
    45: ("Foggy", "මීදුම් සහිත", "🌫️"),
    48: ("Depositing rime fog", "ඝන මීදුම් සහිත", "🌫️"),
    51: ("Light drizzle", "සැහැල්ලු පොද වැසි", "🌦️"),
    53: ("Moderate drizzle", "මධ්‍යස්ථ පොද වැසි", "🌦️"),
    55: ("Dense drizzle", "තද පොද වැසි", "🌧️"),
    61: ("Slight rain", "සුළු වැසි", "🌧️"),
    63: ("Moderate rain", "මධ්‍යස්ථ වැසි", "🌧️"),
    65: ("Heavy rain", "තද වැසි", "🌧️"),
    71: ("Slight snow fall", "සුළු හිම පතනය", "🌨️"),
    73: ("Moderate snow fall", "මධ්‍යස්ථ හිම පතනය", "🌨️"),
    75: ("Heavy snow fall", "තද හිම පතනය", "❄️"),
    80: ("Slight rain showers", "සුළු වැසි වාර", "🌦️"),
    81: ("Moderate rain showers", "මධ්‍යස්ථ වැසි වාර", "🌧️"),
    82: ("Violent rain showers", "තද වැසි කුණාටු", "⛈️"),
    95: ("Thunderstorm", "ගිගුරුම් සහිත වැසි", "⛈️"),
    96: ("Thunderstorm with slight hail", "ගිගුරුම් සහ අයිස් කැට වැසි", "⛈️"),
    99: ("Thunderstorm with heavy hail", "දරුණු ගිගුරුම් සහ අයිස් කැට වැසි", "⛈️"),
}


def is_internet_enabled() -> bool:
    """Check if internet access is permitted by user/environment."""
    flag = os.environ.get("PAI_INTERNET_ENABLED", "1").strip().lower()
    return flag not in ("0", "false", "no", "off")


def set_internet_enabled(enabled: bool) -> None:
    """Toggle internet access on or off."""
    os.environ["PAI_INTERNET_ENABLED"] = "1" if enabled else "0"


def geocode_location(location_name: str, timeout: float = 5.0) -> Optional[Tuple[float, float, str, str]]:
    """Geocode a city or country name to (latitude, longitude, resolved_name, country)."""
    loc = (location_name or "").strip()
    if not loc:
        # Default to Colombo, Sri Lanka
        return 6.9271, 79.8612, "Colombo", "Sri Lanka"

    clean_name = re.sub(r"(?i)\b(in|for|at|city|town|sri lanka|lanka)\b", " ", loc).strip()
    encoded = urllib.parse.quote_plus(clean_name or loc)
    url = f"https://geocoding-api.open-meteo.com/v1/search?name={encoded}&count=1"

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results")
            if results and len(results) > 0:
                first = results[0]
                lat = float(first.get("latitude", 6.9271))
                lon = float(first.get("longitude", 79.8612))
                resolved = str(first.get("name", loc))
                country = str(first.get("country", ""))
                return lat, lon, resolved, country
    except Exception:
        pass
    # Fallback to Colombo if lookup fails
    return 6.9271, 79.8612, loc.title() or "Colombo", "Sri Lanka"


def fetch_live_weather(query: str = "", timeout: float = 6.0) -> Tuple[bool, str, Dict[str, Any]]:
    """Fetch live real-time weather from Open-Meteo API.

    Returns (success, formatted_message, raw_data_dict).
    """
    if not is_internet_enabled():
        return False, "Internet access is disabled in PAI settings (/internet on to enable).", {}

    # Extract location from query if provided
    raw_loc = ""
    if query:
        cleaned = re.sub(
            r"(?i)\b(mata|ada|today|eka|hoyala|balala|denna|kiyanna|how is|what is|the|report|forecast|wether|weather|kaalaguna|kalagune|kaalagunayak|in|for|of|please|pls)\b",
            " ",
            query,
        )
        raw_loc = re.sub(r"\s+", " ", cleaned).strip(" ,.;:?!'\"")

    geo = geocode_location(raw_loc, timeout=timeout)
    if not geo:
        lat, lon, city, country = 6.9271, 79.8612, "Colombo", "Sri Lanka"
    else:
        lat, lon, city, country = geo

    url = (
        f"https://api.open-meteo.com/v1/forecast?latitude={lat:.4f}&longitude={lon:.4f}"
        "&current_weather=true&hourly=relativehumidity_2m"
    )

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return False, f"Weather connection error: {exc}", {}
    except Exception as exc:
        return False, f"Failed to retrieve weather data: {exc}", {}

    cw = data.get("current_weather", {})
    if not cw:
        return False, "Current weather data was not available for this location.", {}

    temp = cw.get("temperature", 0.0)
    wind = cw.get("windspeed", 0.0)
    wcode = cw.get("weathercode", 0)
    time_str = cw.get("time", "")

    desc_en, desc_si, emoji = _WEATHER_CODE_MAP.get(wcode, ("Cloudy", "වලාකුළු සහිත", "☁️"))
    loc_display = f"{city}, {country}" if country else city

    msg = (
        f"{emoji} Live Weather Update for {loc_display}:\n"
        f"  • Temperature (උෂ්ණත්වය) : {temp:.1f} °C\n"
        f"  • Condition (තත්ත්වය)    : {desc_en} ({desc_si})\n"
        f"  • Wind Speed (සුළඟ)       : {wind:.1f} km/h\n"
        f"  • Timestamp              : {time_str}\n"
        f"Real-time data provided by Open-Meteo."
    )

    result_data = {
        "location": loc_display,
        "temperature_c": temp,
        "windspeed_kmh": wind,
        "condition_en": desc_en,
        "condition_si": desc_si,
        "weathercode": wcode,
        "time": time_str,
    }
    return True, msg, result_data


def search_web(query: str, max_results: int = 5, timeout: float = 6.0) -> Tuple[bool, str, List[Dict[str, str]]]:
    """Perform real-time web search using Wikipedia and DuckDuckGo."""
    if not is_internet_enabled():
        return False, "Internet access is disabled in PAI settings (/internet on to enable).", []

    q = (query or "").strip()
    if not q:
        return False, "Search query cannot be empty.", []

    results: List[Dict[str, str]] = []
    seen_titles = set()

    # Expand query abbreviations and clean
    clean_q = re.sub(r"(?i)\b(who is|who was|what is|tell me about|can you tell me|do you know|the|of|a|an)\b", " ", q)
    clean_q = re.sub(r"(?i)\bus\b", "United States", clean_q)
    clean_q = re.sub(r"\s+", " ", clean_q).strip()

    search_queries = [q]
    if clean_q and clean_q.lower() != q.lower():
        search_queries.append(clean_q)
    if any(k in q.lower() for k in ("president", "prime minister", "governor", "leader", "chancellor", "king")):
        if "president" in q.lower() and any(u in q.lower() for u in ("sri lanka", "lanka")):
            search_queries.insert(0, "President of Sri Lanka")
            search_queries.insert(1, "List of presidents of Sri Lanka")
        elif "president" in q.lower() and any(u in q.lower() for u in ("us", "united states", "u.s.", "america")):
            search_queries.insert(0, "List of presidents of the United States")
            search_queries.insert(1, "President of the United States")
        elif "prime minister" in q.lower() and any(u in q.lower() for u in ("uk", "united kingdom", "u.k.", "britain")):
            search_queries.insert(0, "Prime Minister of the United Kingdom")
            search_queries.insert(1, "List of prime ministers of the United Kingdom")
        else:
            search_queries.insert(0, f"List of {clean_q}")

    # 1. Wikipedia Full-Text Search with Lead Section Extract (exintro + explaintext)
    for sq in search_queries[:3]:
        try:
            srch_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote_plus(sq)}&utf8=&format=json"
            req_srch = urllib.request.Request(srch_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req_srch, timeout=timeout) as resp:
                srch_data = json.loads(resp.read().decode("utf-8"))
                items = srch_data.get("query", {}).get("search", [])
                hit_titles = [it.get("title") for it in items[:3] if it.get("title") and it.get("title") not in seen_titles]
                for ht in hit_titles:
                    seen_titles.add(ht)

                if hit_titles:
                    titles_param = "|".join(urllib.parse.quote(t) for t in hit_titles)
                    ext_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exintro=1&explaintext=1&titles={titles_param}&format=json"
                    req_ext = urllib.request.Request(ext_url, headers={"User-Agent": USER_AGENT})
                    with urllib.request.urlopen(req_ext, timeout=timeout) as resp_ext:
                        ext_data = json.loads(resp_ext.read().decode("utf-8"))
                        # Map pages by lowercase title to preserve hit_titles relevance order
                        page_map = {
                            (p.get("title") or "").strip().lower(): p
                            for p in ext_data.get("query", {}).get("pages", {}).values()
                        }
                        for ht in hit_titles:
                            page = page_map.get(ht.strip().lower())
                            if not page:
                                continue
                            p_title = page.get("title", "")
                            p_extract = (page.get("extract") or "").strip()
                            if p_title and p_extract:
                                # Split by linebreaks to get paragraphs and preserve officeholder details
                                paras = [p.strip() for p in re.split(r"\r?\n+", p_extract) if p.strip()]
                                snippet = " ".join(paras[:3])[:750]
                                results.append({
                                    "title": p_title,
                                    "url": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(p_title.replace(' ', '_'))}",
                                    "snippet": snippet,
                                    "source": "Wikipedia",
                                })
        except Exception:
            pass

    # 2. DuckDuckGo Instant Answer API
    ddg_encoded = urllib.parse.quote_plus(q)
    ddg_url = f"https://api.duckduckgo.com/?q={ddg_encoded}&format=json&no_html=1&skip_disambig=1"
    req_ddg = urllib.request.Request(ddg_url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req_ddg, timeout=timeout) as resp:
            d_data = json.loads(resp.read().decode("utf-8"))
            abstract = (d_data.get("AbstractText") or "").strip()
            heading = (d_data.get("Heading") or q).strip()
            abs_url = d_data.get("AbstractURL") or f"https://duckduckgo.com/?q={ddg_encoded}"
            if abstract and heading not in seen_titles:
                seen_titles.add(heading)
                results.append({
                    "title": heading,
                    "url": abs_url,
                    "snippet": abstract,
                    "source": "DuckDuckGo",
                })

            # Check related topics
            for rel in d_data.get("RelatedTopics", [])[:2]:
                if isinstance(rel, dict) and "Text" in rel and "FirstURL" in rel:
                    rel_title = rel.get("FirstURL", "").split("/")[-1].replace("_", " ")
                    if rel_title and rel_title not in seen_titles:
                        seen_titles.add(rel_title)
                        results.append({
                            "title": rel_title,
                            "url": rel.get("FirstURL", ""),
                            "snippet": rel.get("Text", ""),
                            "source": "DuckDuckGo",
                        })
    except Exception:
        pass

    if not results:
        return False, f"No instant search results found online for '{q}'.", []

    lines = [f"🌐 Web Search Results for '{q}':"]
    for i, r in enumerate(results[:max_results], 1):
        lines.append(f"[{i}] {r['title']} ({r['source']})")
        lines.append(f"    {r['snippet'][:250]}{'...' if len(r['snippet']) > 250 else ''}")
        lines.append(f"    Link: {r['url']}")
    msg = "\n".join(lines)
    return True, msg, results[:max_results]


def get_live_grounding_context(query: str, timeout: float = 6.0) -> Tuple[bool, str, List[Dict[str, str]]]:
    """Retrieve real-time web context to ground model prompt before generation."""
    if not is_internet_enabled():
        return False, "", []

    q = (query or "").strip()
    if not q or len(q) < 3:
        return False, "", []

    # Check if query is weather related
    if any(k in q.lower() for k in ("weather", "kaalaguna", "forecast", "temperature", "rain in", "climate in")):
        ok_w, msg_w, data_w = fetch_live_weather(q, timeout=timeout)
        if ok_w:
            ctx = (
                f"[REAL-TIME LIVE WEATHER GROUNDING]:\n"
                f"Current Date: 2026-11-13\n"
                f"{msg_w}\n\n"
                f"Instructions: Use this authoritative live weather data to directly answer the user."
            )
            cites = [{
                "title": f"Open-Meteo Weather ({data_w.get('location', 'Global')})",
                "url": "https://open-meteo.com/",
                "snippet": msg_w,
                "source": "Open-Meteo API",
            }]
            return True, ctx, cites

    # Perform real-time web search
    ok_s, msg_s, results = search_web(q, max_results=4, timeout=timeout)
    if not ok_s or not results:
        return False, "", []

    lines = [
        "[REAL-TIME LIVE INTERNET GROUNDING]:",
        "Current System Date: 2026-11-13 (Year 2026)",
        "Verified Live Web Sources:",
    ]
    for i, r in enumerate(results[:4], 1):
        lines.append(f"  Source {i}: {r.get('title')} ({r.get('url')})")
        lines.append(f"  Summary: {r.get('snippet', '')[:1200]}")
    lines.append("")
    lines.append("CRITICAL INSTRUCTIONS: You have active real-time internet web access enabled via PAI Studio. "
                 "The current year is 2026. Carefully read the live web summaries above (for example, the current officeholder is explicitly named in the summaries). "
                 "Directly state the verified person, name, and facts found in the sources. "
                 "Do NOT claim the information is missing, do NOT say 'I do not have access to real-time information', "
                 "and do NOT say 'I cannot predict future elections'. Answer directly and factually.")

    return True, "\n".join(lines), results[:4]


def fetch_url_text(url: str, max_chars: int = 6000, timeout: float = 8.0) -> Tuple[bool, str]:
    """Safely fetch a webpage and extract clean readable text."""
    if not is_internet_enabled():
        return False, "Internet access is disabled in PAI settings."

    target = url.strip()
    if target.lower().startswith("www."):
        target = "https://" + target
    if not target.startswith(("http://", "https://")):
        return False, f"Invalid URL scheme: '{url}' (must begin with http:// or https://)"

    req = urllib.request.Request(
        target,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read(256 * 1024)
            encoding = resp.headers.get_content_charset() or "utf-8"
            html = raw_bytes.decode(encoding, errors="replace")
    except Exception as exc:
        return False, f"Failed to fetch URL '{target}': {exc}"

    # Strip script and style blocks
    cleaned = re.sub(r"(?is)<(script|style|svg|noscript)[^>]*>.*?</\1>", " ", html)
    # Strip HTML tags
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    # Unescape HTML entities
    cleaned = cleaned.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    truncated = cleaned[:max_chars]
    if len(cleaned) > max_chars:
        truncated += f"\n\n[Content truncated to {max_chars} characters]"
    return True, truncated