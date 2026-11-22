"""Automated Fact-Checking and Web Grounding Engine for PAI.

Evaluates AI-generated statements and factual propositions against live web
references (Wikipedia, DuckDuckGo, Open-Meteo) to identify hallucinations,
verify dates and numbers, and ground model outputs with source citations.

Design & Architectural Foundations:
  - Corrective RAG (CRAG) & Self-RAG verification loops
  - Claim decomposition & entity-relation extraction
  - Entailment and lexical/semantic overlap scoring
  - Automated citation synthesis and trust badges (VERIFIED, UNVERIFIED, CONTRADICTED)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from research.internet_service import (
        fetch_url_text,
        is_internet_enabled,
        search_openalex_works,
        search_web,
        search_wikidata_entities,
    )
except ModuleNotFoundError:
    from internet_service import (
        fetch_url_text,
        is_internet_enabled,
        search_openalex_works,
        search_web,
        search_wikidata_entities,
    )

# Global toggle for automated fact checking in interactive sessions
_AUTO_FACTCHECK_ENABLED: bool = True


def is_factcheck_enabled() -> bool:
    """Return whether automated fact-checking is globally enabled."""
    global _AUTO_FACTCHECK_ENABLED
    return _AUTO_FACTCHECK_ENABLED


def set_factcheck_enabled(enabled: bool) -> None:
    """Enable or disable automated fact-checking."""
    global _AUTO_FACTCHECK_ENABLED
    _AUTO_FACTCHECK_ENABLED = bool(enabled)


@dataclass
class FactualClaim:
    """A single factual claim extracted from model output."""
    statement: str
    entities: List[str]
    keywords: List[str]
    verdict: str  # 'VERIFIED', 'UNVERIFIED', 'CONTRADICTED'
    confidence: float  # 0.0 to 1.0
    citations: List[Dict[str, str]]  # [{'title': ..., 'url': ..., 'snippet': ...}]
    notes: str = ""


# Stopwords to filter out during keyword extraction
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
    "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
    "but", "by", "can", "cannot", "could", "did", "do", "does", "doing", "down", "during", "each",
    "few", "for", "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers",
    "herself", "him", "himself", "his", "how", "i", "if", "in", "into", "is", "isn't", "it", "its",
    "itself", "just", "me", "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off",
    "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "same",
    "she", "should", "so", "some", "such", "than", "that", "the", "their", "theirs", "them",
    "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too",
    "under", "until", "up", "very", "was", "wasn't", "we", "were", "what", "when", "where",
    "which", "while", "who", "whom", "why", "with", "would", "you", "your", "yours", "yourself",
}


def extract_verifiable_claims(text: str, max_claims: int = 3) -> List[str]:
    """Extract candidate factual sentences from generated text.
    
    Filters out greetings, conversational meta-commentary, code blocks,
    and questions, prioritizing statements containing numbers, dates,
    proper nouns, or factual assertions.
    """
    clean_text = re.sub(r"```[\s\S]*?```", "", text)  # remove code blocks
    clean_text = re.sub(r"`[^`]+`", "", clean_text)  # remove inline code
    lines = [ln.strip() for ln in clean_text.splitlines() if ln.strip()]

    candidate_sentences: List[str] = []
    for line in lines:
        # Protect single letter initials (e.g. Donald J. Trump, U.S.) and common titles/abbreviations
        safe = re.sub(r'\b([A-Z])\.\s+', r'\1.<PROTECTED_SPACE>', line)
        safe = re.sub(r'\b(Dr|Mr|Mrs|Ms|Prof|Inc|Corp|Jan|Feb|Mar|Apr|Aug|Sept?|Oct|Nov|Dec|vs|etc)\.\s+', r'\1.<PROTECTED_SPACE>', safe)
        raw_parts = re.split(r'(?<=[.!?])\s+', safe)
        parts = [p.replace('<PROTECTED_SPACE>', ' ') for p in raw_parts]
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if len(p) < 20 or len(p) > 280:
                continue
            if p.endswith("?"):
                continue  # skip questions
            # Exclude obvious conversation filler
            lower = p.lower()
            if any(lower.startswith(prefix) for prefix in [
                "sure", "here is", "let me", "i can help", "as an ai", "hello", "hi ", "ok",
                "yes,", "please note", "i hope this", "feel free"
            ]):
                continue

            # Prioritize sentences with informative tokens (numbers, years, capital words)
            has_digits = bool(re.search(r"\b\d+\b", p))
            has_proper_nouns = len(re.findall(r"\b[A-Z][a-z]{2,}\b", p)) >= 2
            has_factual_markers = any(k in lower for k in [
                "founded", "located", "capital", "population", "invented", "released",
                "developed", "born", "died", "measured", "contains", "known as", "official"
            ])

            score = (2 if has_digits else 0) + (2 if has_proper_nouns else 0) + (3 if has_factual_markers else 0)
            if score >= 2 or len(p.split()) >= 6:
                candidate_sentences.append((score, p))

    # Sort candidates by factual marker score descending
    candidate_sentences.sort(key=lambda x: x[0], reverse=True)
    return [s[1] for s in candidate_sentences[:max_claims]]


def extract_keywords_and_entities(sentence: str) -> Tuple[List[str], List[str]]:
    """Extract search terms and named entities from a sentence."""
    tokens = re.findall(r"[A-Za-z0-9_\-]+", sentence)
    keywords: List[str] = []

    # Proper noun phrases (consecutive capitalized words: e.g. 'Sri Lanka', 'Albert Einstein')
    raw_entities = re.findall(r"\b[A-Z][a-z0-9_\-]+(?:\s+[A-Z][a-z0-9_\-]+)*\b", sentence)
    entities: List[str] = []
    for e in raw_entities:
        clean_e = re.sub(r"^(The|A|An)\s+", "", e.strip(), flags=re.I).strip()
        if clean_e.lower() not in STOPWORDS and len(clean_e) > 2 and clean_e not in entities:
            entities.append(clean_e)

    # General keywords
    for t in tokens:
        tl = t.lower()
        if tl not in STOPWORDS and len(tl) > 2:
            keywords.append(tl)

    return entities, keywords


def evaluate_entailment(
    claim: str,
    evidence_snippets: List[Dict[str, str]],
    entities: Optional[List[str]] = None,
) -> Tuple[str, float, List[Dict[str, str]], str]:
    """Evaluate whether evidence supports, is neutral towards, or refutes a claim.
    
    Returns:
      verdict: 'VERIFIED', 'UNVERIFIED', or 'CONTRADICTED'
      confidence: float between 0.0 and 1.0
      citations: matching citations
      notes: explanation
    """
    if not evidence_snippets:
        return "UNVERIFIED", 0.3, [], "No relevant web evidence retrieved."

    claim_words = set(re.findall(r"[a-z0-9]+", claim.lower())) - STOPWORDS
    claim_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", claim))
    claim_entities = [e.lower() for e in (entities or []) if len(e) > 2]

    best_score = 0.0
    matched_citations: List[Dict[str, str]] = []
    refuting_citations: List[Dict[str, str]] = []
    conflicting_signals = False
    missing_key_entity = False
    temporal_contradiction = False

    past_regex = re.compile(
        r"(?:\b("
        r"was\s+(?:the|an?|elected|appointed|chosen|inaugurated)|"
        r"former\s+(?:president|prime minister|leader|head of state|politician|minister|ceo|ruler|monarch|officer)|"
        r"ex-(?:president|prime minister|leader|ceo)|"
        r"ousted\s+(?:president|leader|ruler)|"
        r"retired\s+(?:politician|officer|leader)|"
        r"served\s+(?:as|from|until)|"
        r"until\s+(?:his|her|their)?\s*resignation|"
        r"resigned\s+(?:in|on|after)|"
        r"stepped\s+down|"
        r"left\s+office|"
        r"predecessor|"
        r"succeeded\s+by"
        r")\b|\(\s*\d{4}\s*[-–—]\s*(?:\d{2,4})\s*\))",
        re.I
    )

    is_current_claim = bool(re.search(
        r"\b(current|sitting|incumbent|now|presently|"
        r"is\s+(?:the\s+)?(?:4[0-9]th\s+|[0-9]+th\s+)?president|"
        r"is\s+(?:the\s+)?prime minister|"
        r"serving\s+as\s+president|"
        r"has\s+been\s+serving\s+since|"
        r"serves\s+as)\b",
        claim,
        re.I
    ))

    for ev in evidence_snippets:
        snippet_text = (ev.get("snippet", "") + " " + ev.get("title", "")).lower()
        snippet_words = set(re.findall(r"[a-z0-9]+", snippet_text)) - STOPWORDS
        snippet_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", snippet_text))

        # Check temporal contradiction for current vs former status
        is_past_evidence = bool(past_regex.search(snippet_text))
        is_contradiction = (is_current_claim and is_past_evidence)
        if is_contradiction:
            conflicting_signals = True
            temporal_contradiction = True
            refuting_citations.append(ev)

        # Word overlap (Jaccard similarity on non-stopwords)
        if not claim_words:
            overlap = 0.0
        else:
            intersection = claim_words.intersection(snippet_words)
            overlap = len(intersection) / len(claim_words)

        # Apply temporal contradiction penalty
        if is_contradiction:
            overlap = min(overlap * 0.10, 0.08)

        # Entity verification
        if claim_entities:
            present_entities = []
            for ent in claim_entities:
                clean_ent = re.sub(r"^(the|a|an)\s+", "", ent, flags=re.I).strip()
                if clean_ent in snippet_text or ent in snippet_text:
                    present_entities.append(ent)
                elif len(clean_ent.split()) >= 2:
                    ent_toks = set(clean_ent.split()) - STOPWORDS
                    if ent_toks and ent_toks.issubset(snippet_words):
                        present_entities.append(ent)

            entity_ratio = len(present_entities) / len(claim_entities)
            if entity_ratio >= 0.70:
                # Majority of entities confirmed in snippet
                if not is_contradiction:
                    overlap = max(overlap, 0.40 + 0.50 * entity_ratio)
                else:
                    overlap = min(overlap, 0.08)
            elif len(claim_entities) >= 2 and len(present_entities) < len(claim_entities):
                # An entity mentioned in claim was not found in snippet
                is_relational = bool(re.search(r"\b(capital\s+of|is\s+the\s+capital|president\s+of|prime\s+minister\s+of|currency\s+of|located\s+in|born\s+in|died\s+in)\b", claim, re.I))
                if is_relational:
                    missing_key_entity = True
                    conflicting_signals = True
                overlap *= 0.70

        # Numerical consistency check
        if claim_numbers:
            matching_nums = claim_numbers.intersection(snippet_numbers)
            if not matching_nums and len(snippet_numbers) > 0:
                # Snippet contained different numbers for the same topic
                overlap *= 0.80
                conflicting_signals = True

        if overlap > best_score:
            best_score = overlap

        if overlap >= 0.45 and not is_contradiction:
            matched_citations.append(ev)

    # Classify verdict based on threshold and conflict signals
    if temporal_contradiction:
        verdict = "CONTRADICTED"
        confidence = 0.95
        matched_citations = refuting_citations[:2] if refuting_citations else matched_citations[:2]
        notes = "Evidence indicates the individual is a former officeholder or resigned, contradicting the claim of current tenure."
    elif best_score >= 0.60:
        verdict = "VERIFIED"
        confidence = min(0.98, round(best_score + 0.10, 2))
        notes = "Corroborated by independent reference data."
    elif conflicting_signals and best_score < 0.40:
        verdict = "CONTRADICTED"
        confidence = 0.75 if missing_key_entity else 0.85
        notes = "Evidence indicates key entities or details contradict web sources."
    elif best_score >= 0.35:
        verdict = "UNVERIFIED"
        confidence = round(best_score, 2)
        notes = "Partially supported, but authoritative details were incomplete."
    else:
        verdict = "UNVERIFIED"
        confidence = round(max(0.2, best_score), 2)
        notes = "Insufficient corroborating evidence found online."

    return verdict, confidence, matched_citations[:2], notes


def verify_text_claims(text: str, max_claims: int = 3) -> List[FactualClaim]:
    """Perform full fact-checking workflow on a block of text."""
    if not is_internet_enabled():
        return []

    candidate_statements = extract_verifiable_claims(text, max_claims=max_claims)
    if not candidate_statements:
        return []

    results: List[FactualClaim] = []
    last_known_subject_entities: List[str] = []

    for stmt in candidate_statements:
        entities, keywords = extract_keywords_and_entities(stmt)

        # Pronoun & orphan referent resolution:
        # If statement starts with a pronoun or lacks named entities, inherit from previous statement
        is_pronoun_stmt = bool(re.match(r"^(he|she|it|they|this|the former|the current)\b", stmt.strip(), re.I))
        if (is_pronoun_stmt or not entities) and last_known_subject_entities:
            for ent in reversed(last_known_subject_entities):
                if ent not in entities:
                    entities.insert(0, ent)
                for w in ent.split():
                    wl = w.lower()
                    if wl not in keywords and wl not in STOPWORDS and len(wl) > 2:
                        keywords.insert(0, wl)

        # Update last known subject if entities found
        if entities:
            potential_subject = [e for e in entities if len(e.split()) >= 2 or (len(e) > 0 and e[0].isupper())]
            if potential_subject:
                last_known_subject_entities = potential_subject
            else:
                last_known_subject_entities = entities

        # Construct focused search query: prefer named entities excluding months/days
        months_days = {"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
        filtered_entities = [e for e in entities if e.lower() not in months_days]
        search_query = ""
        if len(filtered_entities) >= 3:
            search_query = " ".join(filtered_entities[:3])
        elif filtered_entities:
            search_query = " ".join(filtered_entities)
        elif len(keywords) >= 2:
            search_query = " ".join(keywords[:3])
        else:
            search_query = " ".join(keywords)

        if not search_query.strip():
            continue

        success, _, evidence = search_web(search_query, max_results=4)
        # If no results, retry with multiple entities or top keywords
        if not success or not evidence:
            if len(entities) >= 2:
                success, _, evidence = search_web(" ".join(entities[:2]), max_results=3)
            if not success or not evidence:
                fallback_q = " ".join(keywords[:3])
                if fallback_q and fallback_q != search_query:
                    success, _, evidence = search_web(fallback_q, max_results=3)

        evidence = list(evidence or [])

        # Proactively inject structured Wikidata knowledge for extracted entities
        if filtered_entities:
            for ent in filtered_entities[:2]:
                if len(ent) > 3:
                    try:
                        w_items = search_wikidata_entities(ent, max_results=2)
                        for w in w_items:
                            if not any(e.get("url") == w.get("url") for e in evidence):
                                evidence.append(w)
                    except Exception:
                        pass

        # If claim involves science, papers, or algorithms, inject OpenAlex scholarly papers
        if any(k in stmt.lower() for k in ("algorithm", "quantum", "paper", "research", "neural", "deep learning", "transformer", "physics", "biology", "attention")):
            try:
                alex_items = search_openalex_works(" ".join(keywords[:3]), max_results=2)
                for a in alex_items:
                    if not any(e.get("url") == a.get("url") for e in evidence):
                        evidence.append(a)
            except Exception:
                pass

        if not evidence:
            verdict, conf, cites, notes = "UNVERIFIED", 0.25, [], "Web search returned no results."
        else:
            verdict, conf, cites, notes = evaluate_entailment(stmt, evidence, entities=entities)

            # Deep Document Context Fallback:
            # If verdict is UNVERIFIED but candidate citation URLs exist, fetch full article snippet
            # to verify full paragraph context rather than relying on short search snippets
            if verdict == "UNVERIFIED" and cites and cites[0].get("url") and cites[0]["url"].startswith("http"):
                top_url = cites[0]["url"]
                try:
                    ok_fetch, page_text = fetch_url_text(top_url, max_chars=1800)
                    if ok_fetch and page_text and len(page_text) > 120:
                        deep_evidence = [{
                            "title": cites[0].get("title", "Full Source Text"),
                            "url": top_url,
                            "snippet": page_text,
                            "source": cites[0].get("source", "Web Deep Fetch"),
                        }]
                        v_deep, c_deep, cites_deep, n_deep = evaluate_entailment(stmt, deep_evidence + evidence, entities=entities)
                        if v_deep == "VERIFIED":
                            verdict = v_deep
                            conf = c_deep
                            cites = cites_deep
                            notes = f"Corroborated by deep page text from {cites[0].get('title', 'source')}."
                except Exception:
                    pass

            # Multi-Source Cross-Corroboration Bonus
            distinct_sources = set(c.get("source", "") for c in cites if c.get("source"))
            if verdict == "VERIFIED" and len(distinct_sources) >= 2:
                conf = min(0.99, round(conf + 0.05, 2))
                notes = f"Cross-verified by multiple independent sources ({', '.join(sorted(distinct_sources))})."

        results.append(FactualClaim(
            statement=stmt,
            entities=entities,
            keywords=keywords,
            verdict=verdict,
            confidence=conf,
            citations=cites,
            notes=notes,
        ))

    return results


def calculate_information_trust_score(
    claims: List[FactualClaim],
    citations: Optional[List[Dict[str, Any]]] = None,
    is_council: bool = False,
    council_agreement_ratio: float = 1.0,
    is_temporally_unstable: bool = False,
) -> float:
    """Calculates a continuous, multi-factor Information Trust & Confidence score (0.05 to 0.99).
    
    Rather than binary 0.0 or 1.0 step functions, this algorithmic scoring model evaluates:
      1. Effective claim confidence modulated by semantic entailment & verification verdict.
      2. Partial corroboration credit for unverified propositions.
      3. Severe exponential dampening for active contradictions and factual hallucinations.
      4. Independent web citation corroboration & authority domain credibility.
      5. Multi-model consensus convergence (when Model Council is active).
    """
    if not claims:
        # Conversational or factual statement without decomposed claims
        base_trust = 0.82 if citations else 0.75
        if is_council and council_agreement_ratio >= 0.8:
            base_trust = min(0.92, base_trust + 0.08)
        return round(base_trust, 2)

    claim_scores: List[float] = []
    contradiction_count = 0
    verified_count = 0

    for c in claims:
        verdict = (c.verdict or "").upper()
        conf = float(c.confidence if c.confidence is not None else 0.5)
        num_cites = len(c.citations or [])

        if verdict == "VERIFIED":
            verified_count += 1
            # Verified claims scale between 0.72 and 0.98 based on entailment confidence & citations
            phi = 0.70 + 0.25 * conf + min(0.05, 0.025 * num_cites)
            claim_scores.append(min(0.98, phi))
        elif verdict == "UNVERIFIED":
            # Unverified claims are not active falsehoods; they reflect partial evidence or plausible general statements
            # Typically yields nuanced confidence between 0.28 and 0.55
            phi = 0.25 + 0.35 * conf + min(0.08, 0.04 * num_cites)
            claim_scores.append(phi)
        elif verdict == "CONTRADICTED":
            contradiction_count += 1
            # Contradicted claims indicate hallucinated or outdated propositions
            phi = max(0.03, 0.20 * (1.0 - conf))
            claim_scores.append(phi)
        else:
            claim_scores.append(0.50)

    # Base mean confidence across all claims
    mean_score = sum(claim_scores) / max(1, len(claim_scores))

    # Apply penalty for active contradictions
    if contradiction_count > 0:
        dampener = 0.25 ** contradiction_count
        mean_score = mean_score * dampener

    # Bonus for independent citations (only if no active contradictions)
    citation_bonus = 0.0
    if citations and contradiction_count == 0:
        distinct_sources = len(set(cite.get("url", "") for cite in citations if cite.get("url")))
        citation_bonus += min(0.06, distinct_sources * 0.025)
        # Authority domain check (Wikipedia, .gov, .edu, open-meteo, reuters, etc.)
        has_auth_domain = any(
            any(auth in (cite.get("url") or "").lower() for auth in ["wikipedia.org", ".gov", ".edu", "open-meteo", "reuters", "bbc", "apnews"])
            for cite in citations
        )
        if has_auth_domain:
            citation_bonus += 0.03

    # Multi-model council convergence bonus
    council_factor = 0.0
    if is_council:
        if council_agreement_ratio >= 0.75:
            council_factor = 0.05 * council_agreement_ratio
        elif council_agreement_ratio < 0.40:
            council_factor = -0.08

    # Temporal instability penalty if dynamic facts lacked verified citations
    temporal_penalty = 0.0
    if is_temporally_unstable and verified_count == 0:
        temporal_penalty = 0.12

    final_score = mean_score + citation_bonus + council_factor - temporal_penalty

    # Clamp to realistic continuous range: if contradictions exist, cap strictly at <= 0.15
    if contradiction_count > 0:
        clamped_score = min(0.15, max(0.04, final_score))
    else:
        clamped_score = max(0.08, min(0.98, final_score))
    return round(clamped_score, 2)


def format_factcheck_report(claims: List[FactualClaim], trust_score: Optional[float] = None) -> str:
    """Format verification claims into a readable user-facing audit block."""
    if not claims:
        return ""

    lines = [
        "────────────────────────────────────────────────────────────────────────────────",
        "FACT-CHECK & WEB GROUNDING ENGINE (Live Verification):",
    ]

    verified_count = 0
    total_count = len(claims)

    for i, c in enumerate(claims, 1):
        if c.verdict == "VERIFIED":
            icon = "[VERIFIED]"
            verified_count += 1
        elif c.verdict == "CONTRADICTED":
            icon = "[POTENTIAL HALLUCINATION]"
        else:
            icon = "[UNVERIFIED]"

        lines.append(f"  {i}. {icon} {c.statement}")
        lines.append(f"     Confidence: {int(c.confidence * 100)}% | Note: {c.notes}")
        if c.citations:
            for cite in c.citations:
                title = cite.get("title") or "Web Reference"
                url = cite.get("url") or ""
                lines.append(f"     • Source: {title} ({url})")

    fidelity_rate = int(round(trust_score * 100)) if trust_score is not None else int((verified_count / max(1, total_count)) * 100)
    lines.append(f"Grounding Fidelity: {fidelity_rate}% ({verified_count}/{total_count} claims substantiated).")
    lines.append("────────────────────────────────────────────────────────────────────────────────")

    return "\n".join(lines)
