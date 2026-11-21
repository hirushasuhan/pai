"""PAI Writing Voice Profile & Stylometry Engine.

Inspired by Anthropic's Cowork `setup-writing-style`:
Learns how the user writes from their own authored text, notes, and messages,
building an authentic Voice Profile so generated text sounds like the user
rather than a generic AI (avoiding AI clichés like 'delve', 'leverage', 'robust').

Key Dimensions:
  - Voice: Constant syntactic rhythm, sentence length, and vocabulary.
  - Tone: Adjusts based on audience (customer, team, personal).
  - Surface: Adjusts based on container (email, chat, documentation).
  - PII Scrubbing: Automatically purges sensitive personal details.
"""

from __future__ import annotations

import json
import math
import re
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# AI cliché words to track and avoid
AI_CLICHE_WORDS = {
    "delve", "leverage", "robust", "seamless", "streamline", "pivotal",
    "crucial", "crucially", "notably", "furthermore", "moreover",
    "additionally", "comprehensive", "holistic", "landscape", "ecosystem",
    "utilize", "foster", "empower", "elevate", "testament", "tapestry",
}

# Common contractions
CONTRACTION_REGEX = re.compile(
    r"\b\w+'(?:t|re|ve|ll|d|m)\b|\b(?:it|that|there|he|she|what|who|let|here|where|how)'s\b",
    re.IGNORECASE,
)

# Common greetings and sign-offs
GREETING_REGEX = re.compile(r"^(hi|hey|hello|dear|good (morning|afternoon)|yo|howdy)\b", re.IGNORECASE)
SIGN_OFF_REGEX = re.compile(r"^(thanks|thank you|best|cheers|regards|talk soon|warmly|sincerely|ty|thx)\b", re.IGNORECASE)

# PII Scrubber patterns
PII_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PII_PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
PII_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
PII_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def scrub_pii(text: str) -> str:
    """Removes sensitive personal data from text before stylometric analysis."""
    clean = PII_EMAIL.sub("[EMAIL]", text)
    clean = PII_PHONE.sub("[PHONE]", clean)
    clean = PII_CARD.sub("[CARD_NUM]", clean)
    clean = PII_SSN.sub("[SSN]", clean)
    return clean


def strip_quoted_tails_and_signatures(text: str) -> str:
    """Strips reply headers, forwarded text, and signature blocks."""
    # Strip forwarded markers
    text = re.split(r"-{5,}\s*Forwarded message\s*-{5,}", text, flags=re.IGNORECASE)[0]
    # Strip reply tails
    text = re.split(r"\n+On\s+.{5,80}wrote:\s*\n", text, flags=re.IGNORECASE)[0]
    # Strip signature lines
    text = re.split(r"\n--\s*\n|\nSent from my\b|\nGet Outlook for\b", text, flags=re.IGNORECASE)[0]
    return text.strip()


def tokenize(text: str) -> List[str]:
    """Extracts lowercase words, including Unicode characters and internal apostrophes."""
    return [w.lower() for w in re.findall(r"[^\W\d_]+(?:['’][^\W\d_]+)*", text)]


def split_sentences(text: str) -> List[str]:
    """Splits text into sentences based on punctuation and paragraph breaks."""
    raw = re.split(r"(?<=[.!?])\s+|\n{2,}", text)
    return [s.strip() for s in raw if re.search(r"\w", s)]


@dataclass
class StylometricMetrics:
    total_words: int
    total_sentences: int
    mean_sentence_length: float
    stdev_sentence_length: float
    type_token_ratio: float  # Vocabulary richness
    contraction_rate_per_100: float
    bullet_rate_per_1000_words: float
    ai_cliche_density_per_1000: float
    preferred_greeting: Optional[str] = None
    preferred_sign_off: Optional[str] = None
    preferred_tone: str = "concise, warm, direct"


@dataclass
class WritingVoiceProfile:
    user_id: str
    sample_count: int
    metrics: StylometricMetrics
    guidelines: List[str] = field(default_factory=list)
    forbidden_words: List[str] = field(default_factory=list)
    created_at: str = ""


class StylometryAnalyzer:
    """Analyzes a collection of user writing samples to create a Voice Profile."""

    def __init__(self):
        pass

    def analyze_samples(
        self,
        samples: List[str],
        user_id: str = "default_user",
        preferred_tone: Optional[str] = None,
    ) -> WritingVoiceProfile:
        """Processes multiple text samples and computes aggregate stylometrics."""
        cleaned_samples = []
        for s in samples:
            c = scrub_pii(strip_quoted_tails_and_signatures(s))
            if len(tokenize(c)) >= 8:  # filter trivial single-word messages
                cleaned_samples.append(c)

        tone_str = preferred_tone or "concise, direct, technical"

        if not cleaned_samples:
            # Fallback default profile if no samples provided
            default_metrics = StylometricMetrics(
                total_words=0,
                total_sentences=0,
                mean_sentence_length=14.0,
                stdev_sentence_length=4.5,
                type_token_ratio=0.65,
                contraction_rate_per_100=2.0,
                bullet_rate_per_1000_words=0.0,
                ai_cliche_density_per_1000=0.0,
                preferred_tone=tone_str,
            )
            return WritingVoiceProfile(
                user_id=user_id,
                sample_count=0,
                metrics=default_metrics,
                guidelines=[
                    f"Author tone orientation: {tone_str}.",
                    "Keep sentences concise (12-16 words).",
                    "Use natural conversational contractions.",
                    "Strictly avoid generic corporate AI jargon ('delve', 'leverage', 'robust', 'seamless', 'ecosystem').",
                ],
                forbidden_words=list(AI_CLICHE_WORDS)[:12],
            )

        all_words: List[str] = []
        sentence_lengths: List[int] = []
        contraction_count = 0
        bullet_count = 0
        cliche_count = 0
        greetings: List[str] = []
        sign_offs: List[str] = []

        for sample in cleaned_samples:
            words = tokenize(sample)
            all_words.extend(words)

            sents = split_sentences(sample)
            for sent in sents:
                swords = tokenize(sent)
                if swords:
                    sentence_lengths.append(len(swords))

            # Contractions
            contraction_count += len(CONTRACTION_REGEX.findall(sample))

            # Bullet points
            bullet_count += len(re.findall(r"^\s*[-*•]|\s*\d+[.)]", sample, re.MULTILINE))

            # AI Clichés
            for w in words:
                if w in AI_CLICHE_WORDS:
                    cliche_count += 1

            # First and last sentence for greetings / closings
            if sents:
                first_sent = sents[0].strip()
                gm = GREETING_REGEX.search(first_sent)
                if gm:
                    greetings.append(gm.group(1).capitalize())

                last_sent = sents[-1].strip()
                sm = SIGN_OFF_REGEX.search(last_sent)
                if sm:
                    sign_offs.append(sm.group(1).capitalize())

        total_words = len(all_words)
        total_sents = len(sentence_lengths)
        mean_sent_len = statistics.mean(sentence_lengths) if sentence_lengths else 14.0
        stdev_sent_len = statistics.stdev(sentence_lengths) if len(sentence_lengths) > 1 else 3.0
        ttr = len(set(all_words)) / max(total_words, 1)

        contraction_rate = (contraction_count / max(total_words, 1)) * 100.0
        bullet_rate = (bullet_count / max(total_words, 1)) * 1000.0
        cliche_rate = (cliche_count / max(total_words, 1)) * 1000.0

        pref_greeting = max(set(greetings), key=greetings.count) if greetings else None
        pref_sign_off = max(set(sign_offs), key=sign_offs.count) if sign_offs else None

        # Build specific guidelines based on the metrics
        guidelines = [
            f"Author tone orientation: {tone_str}.",
            f"Target sentence length: ~{round(mean_sent_len)} words per sentence (variance: ±{round(stdev_sent_len)}).",
            "Prefer standard contractions (e.g. 'I'm', 'don't', 'we'll') to maintain natural flow." if contraction_rate >= 1.5 else "Avoid heavy contractions; use clear, standard phrasing.",
            "Write predominantly in clean prose paragraphs. Minimize or avoid bullet lists." if bullet_rate < 5.0 else "Use clean, scannable lists when outlining multi-part concepts.",
            "Strictly avoid generic corporate AI jargon ('delve', 'leverage', 'robust', 'seamless', 'ecosystem', 'tapestry').",
        ]
        if pref_greeting:
            guidelines.append(f"Preferred message opening: '{pref_greeting}'.")
        if pref_sign_off:
            guidelines.append(f"Preferred message sign-off: '{pref_sign_off}'.")

        metrics = StylometricMetrics(
            total_words=total_words,
            total_sentences=total_sents,
            mean_sentence_length=round(mean_sent_len, 1),
            stdev_sentence_length=round(stdev_sent_len, 1),
            type_token_ratio=round(ttr, 3),
            contraction_rate_per_100=round(contraction_rate, 2),
            bullet_rate_per_1000_words=round(bullet_rate, 1),
            ai_cliche_density_per_1000=round(cliche_rate, 2),
            preferred_greeting=pref_greeting,
            preferred_sign_off=pref_sign_off,
            preferred_tone=tone_str,
        )

        import datetime
        return WritingVoiceProfile(
            user_id=user_id,
            sample_count=len(cleaned_samples),
            metrics=metrics,
            guidelines=guidelines,
            forbidden_words=list(AI_CLICHE_WORDS),
            created_at=datetime.datetime.now().isoformat(),
        )

    def save_profile(self, profile: WritingVoiceProfile, dest_path: Optional[Path] = None) -> Path:
        """Saves writing voice profile to ~/.pai/memory/voice_profile.json."""
        if dest_path is None:
            dest_dir = Path.home() / ".pai" / "memory"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / "voice_profile.json"

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        # Convert dataclasses to serializable dict
        data = {
            "user_id": profile.user_id,
            "sample_count": profile.sample_count,
            "metrics": asdict(profile.metrics),
            "guidelines": profile.guidelines,
            "forbidden_words": profile.forbidden_words,
            "created_at": profile.created_at,
        }
        dest_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return dest_path

    def delete_profile(self, dest_path: Optional[Path] = None) -> bool:
        """Deletes writing voice profile from disk."""
        if dest_path is None:
            dest_path = Path.home() / ".pai" / "memory" / "voice_profile.json"
        if dest_path.is_file():
            try:
                dest_path.unlink()
                return True
            except Exception:
                return False
        return False

    def load_profile(self, source_path: Optional[Path] = None) -> Optional[WritingVoiceProfile]:
        """Loads writing voice profile from disk."""
        if source_path is None:
            source_path = Path.home() / ".pai" / "memory" / "voice_profile.json"

        if not source_path.is_file():
            return None

        try:
            data = json.loads(source_path.read_text(encoding="utf-8"))
            m = StylometricMetrics(**data["metrics"])
            return WritingVoiceProfile(
                user_id=data.get("user_id", "default"),
                sample_count=data.get("sample_count", 0),
                metrics=m,
                guidelines=data.get("guidelines", []),
                forbidden_words=data.get("forbidden_words", []),
                created_at=data.get("created_at", ""),
            )
        except Exception:
            return None

    def format_voice_prompt(self, profile: WritingVoiceProfile) -> str:
        """Formats writing style profile into clear prompt instructions."""
        rules = "\n".join([f"- {g}" for g in profile.guidelines])
        forbidden = ", ".join(profile.forbidden_words[:12])
        return (
            f"Author Writing Style & Persona Guidelines:\n"
            f"{rules}\n"
            f"- Forbidden AI Clichés: Strictly avoid generic AI jargon ({forbidden})."
        )
