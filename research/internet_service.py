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

USER_AGENT = "PersonalAgenticAI/1.1 (Interactive Assistant; Windows x64)"

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

    # 1. Wikipedia Summary Search (Direct title match or search query)
    wiki_encoded = urllib.parse.quote(q.replace(" ", "_"), safe="")
    wiki_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{wiki_encoded}"
    req_wiki = urllib.request.Request(wiki_url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req_wiki, timeout=timeout) as resp:
            w_data = json.loads(resp.read().decode("utf-8"))
            extract = (w_data.get("extract") or "").strip()
            title = (w_data.get("title") or q).strip()
            page_url = w_data.get("content_urls", {}).get("desktop", {}).get("page", f"https://en.wikipedia.org/wiki/{wiki_encoded}")
            if extract:
                results.append({
                    "title": title,
                    "url": page_url,
                    "snippet": extract,
                    "source": "Wikipedia",
                })
    except Exception:
        # Fallback to Wikipedia Full-Text Search API
        try:
            srch_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote_plus(q)}&utf8=&format=json"
            req_srch = urllib.request.Request(srch_url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req_srch, timeout=timeout) as resp:
                srch_data = json.loads(resp.read().decode("utf-8"))
                items = srch_data.get("query", {}).get("search", [])
                for it in items[:2]:
                    it_title = it.get("title", "")
                    raw_snip = it.get("snippet", "")
                    clean_snip = re.sub(r"<[^>]+>", "", raw_snip).strip()
                    if it_title and clean_snip:
                        results.append({
                            "title": it_title,
                            "url": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(it_title.replace(' ', '_'))}",
                            "snippet": clean_snip,
                            "source": "Wikipedia Search",
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
            if abstract:
                results.append({
                    "title": heading,
                    "url": abs_url,
                    "snippet": abstract,
                    "source": "DuckDuckGo",
                })

            # Check related topics
            for rel in d_data.get("RelatedTopics", [])[:3]:
                if isinstance(rel, dict) and "Text" in rel and "FirstURL" in rel:
                    results.append({
                        "title": rel.get("FirstURL", "").split("/")[-1].replace("_", " "),
                        "url": rel.get("FirstURL", ""),
                        "snippet": rel.get("Text", ""),
                        "source": "DuckDuckGo Related",
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