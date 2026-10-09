"""
Mutant Benchmark for Gate Recall Experiment
Contains 42 realistic buggy implementations (mutants) across coding tasks code_01 - code_20.
Every mutant MUST fail the hidden reference test suite (verified by test_mutants.py).
The adopted verification gate MUST reject 100% of these mutants (0 false accepts).
"""

from typing import Any, Callable, Dict, List, Tuple


MUTANTS: List[Dict[str, Any]] = [
    # code_01: parse_simple_csv
    {
        "id": "code_01_mutant_1",
        "task_id": "code_01",
        "description": "Fails to strip outer whitespace from cell values",
        "code": '''
def parse_simple_csv(csv_text: str):
    if not csv_text or not csv_text.strip():
        return []
    lines = [l for l in csv_text.splitlines() if l.strip()]
    if len(lines) <= 1:
        return []
    headers = [h.strip() for h in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        # Bug: Does not strip whitespace from row values
        vals = line.split(",")
        rows.append(dict(zip(headers, vals)))
    return rows
''',
    },
    {
        "id": "code_01_mutant_2",
        "task_id": "code_01",
        "description": "Naive comma split breaks on quoted strings with internal commas",
        "code": '''
def parse_simple_csv(csv_text: str):
    if not csv_text or not csv_text.strip():
        return []
    lines = [l for l in csv_text.splitlines() if l.strip()]
    if len(lines) <= 1:
        return []
    headers = [h.strip() for h in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        # Bug: naively splits on comma without respecting quotation marks
        vals = [v.strip() for v in line.split(",")]
        rows.append(dict(zip(headers, vals)))
    return rows
''',
    },
    # code_02: safe_json_path_lookup
    {
        "id": "code_02_mutant_1",
        "task_id": "code_02",
        "description": "Returns None instead of default argument on missing key/index",
        "code": '''
def safe_json_path_lookup(data, path: str, default=None):
    if not path:
        return data
    curr = data
    for part in path.split("."):
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        elif isinstance(curr, list) and part.isdigit() and int(part) < len(curr):
            curr = curr[int(part)]
        else:
            return None  # Bug: returns hardcoded None instead of default
    return curr
''',
    },
    {
        "id": "code_02_mutant_2",
        "task_id": "code_02",
        "description": "Off-by-one in list indexing lookup (1-based instead of 0-based)",
        "code": '''
def safe_json_path_lookup(data, path: str, default=None):
    if not path:
        return data
    curr = data
    for part in path.split("."):
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        elif isinstance(curr, list) and part.isdigit():
            idx = int(part) - 1  # Bug: 1-based indexing
            if 0 <= idx < len(curr):
                curr = curr[idx]
            else:
                return default
        else:
            return default
    return curr
''',
    },
    # code_03: compact_number_formatter
    {
        "id": "code_03_mutant_1",
        "task_id": "code_03",
        "description": "Off-by-one threshold: formats 1000 as '1000' instead of '1K'",
        "code": '''
def compact_number_formatter(n):
    sign = "-" if n < 0 else ""
    val = abs(n)
    if val > 1000000000:
        res = f"{val / 1000000000:.1f}".rstrip("0").rstrip(".")
        return f"{sign}{res}B"
    if val > 1000000:
        res = f"{val / 1000000:.1f}".rstrip("0").rstrip(".")
        return f"{sign}{res}M"
    if val > 1000:  # Bug: strict > instead of >=, so 1000 is not formatted as 1K
        res = f"{val / 1000:.1f}".rstrip("0").rstrip(".")
        return f"{sign}{res}K"
    return f"{sign}{val}"
''',
    },
    {
        "id": "code_03_mutant_2",
        "task_id": "code_03",
        "description": "Loses negative sign for formatted numbers",
        "code": '''
def compact_number_formatter(n):
    val = abs(n)  # Bug: ignores sign in final output
    if val >= 1000000000:
        res = f"{val / 1000000000:.1f}".rstrip("0").rstrip(".")
        return f"{res}B"
    if val >= 1000000:
        res = f"{val / 1000000:.1f}".rstrip("0").rstrip(".")
        return f"{res}M"
    if val >= 1000:
        res = f"{val / 1000:.1f}".rstrip("0").rstrip(".")
        return f"{res}K"
    return f"{n}"
''',
    },
    # code_04: validate_password_strength
    {
        "id": "code_04_mutant_1",
        "task_id": "code_04",
        "description": "Lax threshold: marks password as valid if score >= 4 instead of 5",
        "code": '''
def validate_password_strength(pw: str) -> dict:
    missing = []
    if len(pw) < 8:
        missing.append("length")
    if not any(c.isupper() for c in pw):
        missing.append("uppercase")
    if not any(c.islower() for c in pw):
        missing.append("lowercase")
    if not any(c.isdigit() for c in pw):
        missing.append("digit")
    specials = set("!@#$%^&*()-_=+[]{}")
    if not any(c in specials for c in pw):
        missing.append("special")
    score = 5 - len(missing)
    # Bug: considers valid if score >= 4 (missing 1 requirement)
    return {"valid": score >= 4, "score": score, "missing": missing}
''',
    },
    {
        "id": "code_04_mutant_2",
        "task_id": "code_04",
        "description": "Inverted condition: allows password with missing digit",
        "code": '''
def validate_password_strength(pw: str) -> dict:
    missing = []
    if len(pw) < 8:
        missing.append("length")
    if not any(c.isupper() for c in pw):
        missing.append("uppercase")
    if not any(c.islower() for c in pw):
        missing.append("lowercase")
    # Bug: forgotten digit check
    specials = set("!@#$%^&*()-_=+[]{}")
    if not any(c in specials for c in pw):
        missing.append("special")
    score = 5 - len(missing)
    return {"valid": score == 5, "score": score, "missing": missing}
''',
    },
    # code_05: top_k_frequent_words
    {
        "id": "code_05_mutant_1",
        "task_id": "code_05",
        "description": "Reversed alphabetical tie-breaker (descending instead of ascending)",
        "code": '''
import re
from collections import Counter

def top_k_frequent_words(text: str, k: int):
    if k <= 0 or not text:
        return []
    words = re.findall(r'[a-zA-Z0-9]+', text.lower())
    if not words:
        return []
    counts = Counter(words)
    # Bug: sorts tie-breaker descending reverse alphabetical
    sorted_words = sorted(counts.keys(), key=lambda w: (-counts[w], w), reverse=True)
    return sorted_words[:k]
''',
    },
    {
        "id": "code_05_mutant_2",
        "task_id": "code_05",
        "description": "Does not handle k <= 0, returns full list",
        "code": '''
import re
from collections import Counter

def top_k_frequent_words(text: str, k: int):
    words = re.findall(r'[a-zA-Z0-9]+', text.lower())
    if not words:
        return []
    counts = Counter(words)
    sorted_words = sorted(counts.keys(), key=lambda w: (-counts[w], w))
    # Bug: when k <= 0, returns full list instead of []
    return sorted_words if k <= 0 else sorted_words[:k]
''',
    },
    # code_06: time_diff_humanized
    {
        "id": "code_06_mutant_1",
        "task_id": "code_06",
        "description": "Returns empty string instead of '0s' for 0 seconds",
        "code": '''
def time_diff_humanized(seconds: int) -> str:
    # Bug: 0 returns empty string
    if seconds == 0:
        return ""
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    secs = seconds % 60
    parts = []
    if days: parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    if secs: parts.append(f"{secs}s")
    return " ".join(parts)
''',
    },
    {
        "id": "code_06_mutant_2",
        "task_id": "code_06",
        "description": "Includes zero units in duration output",
        "code": '''
def time_diff_humanized(seconds: int) -> str:
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    secs = seconds % 60
    # Bug: always outputs all components including 0
    return f"{days}d {hours}h {minutes}m {secs}s"
''',
    },
    # code_07: clean_phone_number
    {
        "id": "code_07_mutant_1",
        "task_id": "code_07",
        "description": "Fails to convert 00 country prefix to +",
        "code": '''
import re

def clean_phone_number(raw: str, default_country_code: str = "+94"):
    cleaned = re.sub(r'[\\s\\-\\(\\)\\.]', '', raw)
    # Bug: fails to convert 00 to +
    if cleaned.startswith("0") and not cleaned.startswith("00") and len(cleaned) == 10:
        cleaned = default_country_code + cleaned[1:]
    if cleaned.startswith("+") and 11 <= len(cleaned) <= 16:
        return cleaned
    return None
''',
    },
    {
        "id": "code_07_mutant_2",
        "task_id": "code_07",
        "description": "Always overrides existing country code with default country code",
        "code": '''
import re

def clean_phone_number(raw: str, default_country_code: str = "+94"):
    cleaned = re.sub(r'[\\s\\-\\(\\)\\.]', '', raw)
    digits = re.sub(r'\\D', '', cleaned)
    if len(digits) < 10:
        return None
    # Bug: blindly prepends default_country_code
    return default_country_code + digits[-9:]
''',
    },
    # code_08: find_first_missing_positive
    {
        "id": "code_08_mutant_1",
        "task_id": "code_08",
        "description": "Returns 0 as missing positive integer",
        "code": '''
def find_first_missing_positive(nums: list[int]) -> int:
    s = set(nums)
    # Bug: checks 0 first (0 is not a positive integer)
    if 0 not in s:
        return 0
    cand = 1
    while cand in s:
        cand += 1
    return cand
''',
    },
    {
        "id": "code_08_mutant_2",
        "task_id": "code_08",
        "description": "Off-by-one: starts search at 2 instead of 1",
        "code": '''
def find_first_missing_positive(nums: list[int]) -> int:
    s = set(nums)
    cand = 2  # Bug: skips 1
    while cand in s:
        cand += 1
    return cand
''',
    },
    # code_09: generate_slug
    {
        "id": "code_09_mutant_1",
        "task_id": "code_09",
        "description": "Does not lower-case ASCII letters",
        "code": '''
import re

def generate_slug(title: str, max_length: int = 50) -> str:
    # Bug: does not call .lower()
    cleaned = re.sub(r'[^a-zA-Z0-9]+', '-', title).strip('-')
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
        last_h = cleaned.rfind('-')
        if last_h != -1:
            cleaned = cleaned[:last_h]
    return cleaned.strip('-')
''',
    },
    {
        "id": "code_09_mutant_2",
        "task_id": "code_09",
        "description": "Fails to trim outer hyphens from beginning and end",
        "code": '''
import re

def generate_slug(title: str, max_length: int = 50) -> str:
    # Bug: does not trim leading and trailing hyphens
    cleaned = re.sub(r'[^a-zA-Z0-9]+', '-', title.lower())
    if not cleaned:
        return ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned
''',
    },
    # code_10: calculate_tax_bracket
    {
        "id": "code_10_mutant_1",
        "task_id": "code_10",
        "description": "Charges fixed base tax on zero and negative income",
        "code": '''
def calculate_tax_bracket(income: float, brackets: list[tuple[float, float]]) -> float:
    # Bug: charges flat minimum fee of 50.0 on zero or negative income
    if income <= 0:
        return 50.0
    prev_limit = 0.0
    tax = 0.0
    for limit, rate in brackets:
        if income > prev_limit:
            taxable = min(income, limit) - prev_limit
            tax += taxable * rate
            prev_limit = limit
        else:
            break
    return round(tax, 2)
''',
    },
    {
        "id": "code_10_mutant_2",
        "task_id": "code_10",
        "description": "Flat bracket calculation instead of progressive segments",
        "code": '''
def calculate_tax_bracket(income: float, brackets: list[tuple[float, float]]) -> float:
    if income <= 0:
        return 0.0
    # Bug: applies highest matching rate to entire income
    for limit, rate in brackets:
        if income <= limit:
            return round(income * rate, 2)
    return round(income * brackets[-1][1], 2)
''',
    },
    # code_11: fuzzy_search_score
    {
        "id": "code_11_mutant_1",
        "task_id": "code_11",
        "description": "Returns negative scores on match",
        "code": '''
def fuzzy_search_score(query: str, target: str) -> int:
    # Bug: inverted score
    return -len(query)
''',
    },
    {
        "id": "code_11_mutant_2",
        "task_id": "code_11",
        "description": "Returns 0 for exact match",
        "code": '''
def fuzzy_search_score(query: str, target: str) -> int:
    if query == target:
        return 0  # Bug: exact match gives 0
    return 1 if query in target else 0
''',
    },
    # code_12: simple_caesar_cipher
    {
        "id": "code_12_mutant_1",
        "task_id": "code_12",
        "description": "Inverts shift direction (subtracts instead of adds)",
        "code": '''
def simple_caesar_cipher(text: str, shift: int) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            # Bug: subtracts shift instead of adding
            res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)
''',
    },
    {
        "id": "code_12_mutant_2",
        "task_id": "code_12",
        "description": "Corrupts non-alphabetic characters like punctuation",
        "code": '''
def simple_caesar_cipher(text: str, shift: int) -> str:
    res = []
    for c in text:
        # Bug: shifts ALL ascii characters including spaces and punctuation
        res.append(chr((ord(c) + shift) % 128))
    return "".join(res)
''',
    },
    # code_13: matrix_transpose_ragged
    {
        "id": "code_13_mutant_1",
        "task_id": "code_13",
        "description": "Drops ragged elements without fill_value padding",
        "code": '''
def matrix_transpose_ragged(matrix: list[list[any]], fill_value: any = None) -> list[list[any]]:
    if not matrix or all(len(r) == 0 for r in matrix):
        return []
    # Bug: zip without zip_longest drops longer rows
    return [list(col) for col in zip(*matrix)]
''',
    },
    {
        "id": "code_13_mutant_2",
        "task_id": "code_13",
        "description": "Returns original matrix without transposing",
        "code": '''
def matrix_transpose_ragged(matrix: list[list[any]], fill_value: any = None) -> list[list[any]]:
    if not matrix or all(len(r) == 0 for r in matrix):
        return []
    # Bug: returns identity without transposing
    return [list(r) for r in matrix]
''',
    },
    # code_14: run_length_compress
    {
        "id": "code_14_mutant_1",
        "task_id": "code_14",
        "description": "Off-by-one count: 0-indexed run lengths",
        "code": '''
def run_length_compress(items: list[any]) -> list[tuple[any, int]]:
    if not items:
        return []
    out = []
    curr = items[0]
    count = 0  # Bug: 0-indexed count
    for x in items[1:]:
        if x == curr:
            count += 1
        else:
            out.append((curr, count))
            curr = x
            count = 0
    out.append((curr, count))
    return out
''',
    },
    {
        "id": "code_14_mutant_2",
        "task_id": "code_14",
        "description": "Aggregates non-consecutive duplicate runs globally",
        "code": '''
from collections import Counter

def run_length_compress(items: list[any]) -> list[tuple[any, int]]:
    # Bug: counts globally instead of consecutive runs
    counts = Counter(items)
    return list(counts.items())
''',
    },
    # code_15: parse_duration_string
    {
        "id": "code_15_mutant_1",
        "task_id": "code_15",
        "description": "Ignores seconds component 's'",
        "code": '''
import re

def parse_duration_string(s: str) -> int:
    matches = re.findall(r'(\\d+)([dhms])', s)
    total = 0
    for val, unit in matches:
        v = int(val)
        if unit == 'd': total += v * 86400
        elif unit == 'h': total += v * 3600
        elif unit == 'm': total += v * 60
        # Bug: drops 's' component
    return total
''',
    },
    {
        "id": "code_15_mutant_2",
        "task_id": "code_15",
        "description": "Assumes minutes are 100 seconds instead of 60 seconds",
        "code": '''
import re

def parse_duration_string(s: str) -> int:
    matches = re.findall(r'(\\d+)([dhms])', s)
    total = 0
    for val, unit in matches:
        v = int(val)
        if unit == 'd': total += v * 86400
        elif unit == 'h': total += v * 3600
        elif unit == 'm': total += v * 100  # Bug: 100s per minute
        elif unit == 's': total += v
    return total
''',
    },
    # code_16: sliding_window_median
    {
        "id": "code_16_mutant_1",
        "task_id": "code_16",
        "description": "Computes window mean instead of window median",
        "code": '''
def sliding_window_median(nums: list[float], k: int) -> list[float]:
    if not nums or k <= 0 or k > len(nums):
        return []
    res = []
    for i in range(len(nums) - k + 1):
        win = nums[i:i+k]
        # Bug: calculates mean instead of median
        res.append(sum(win) / k)
    return res
''',
    },
    {
        "id": "code_16_mutant_2",
        "task_id": "code_16",
        "description": "Off-by-one on window size (uses k-1 items)",
        "code": '''
def sliding_window_median(nums: list[float], k: int) -> list[float]:
    if not nums or k <= 0 or k > len(nums):
        return []
    res = []
    # Bug: window size k-1
    for i in range(len(nums) - k + 1):
        win = sorted(nums[i:i+k-1])
        res.append(win[len(win)//2])
    return res
''',
    },
    # code_17: CircularBuffer
    {
        "id": "code_17_mutant_1",
        "task_id": "code_17",
        "description": "Always accepts enqueue even when buffer is full",
        "code": '''
class CircularBuffer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.data = []

    def enqueue(self, item) -> bool:
        # Bug: does not reject when full
        self.data.append(item)
        return True

    def dequeue(self):
        return self.data.pop(0) if self.data else None

    def peek(self):
        return self.data[0] if self.data else None

    def is_empty(self) -> bool:
        return len(self.data) == 0

    def is_full(self) -> bool:
        return len(self.data) >= self.capacity

    def size(self) -> int:
        return len(self.data)
''',
    },
    {
        "id": "code_17_mutant_2",
        "task_id": "code_17",
        "description": "Dequeue acts as LIFO stack (pop from end) instead of FIFO queue",
        "code": '''
class CircularBuffer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.data = []

    def enqueue(self, item) -> bool:
        if len(self.data) >= self.capacity:
            return False
        self.data.append(item)
        return True

    def dequeue(self):
        # Bug: pop from end (LIFO)
        return self.data.pop() if self.data else None

    def peek(self):
        return self.data[0] if self.data else None

    def is_empty(self) -> bool:
        return len(self.data) == 0

    def is_full(self) -> bool:
        return len(self.data) >= self.capacity

    def size(self) -> int:
        return len(self.data)
''',
    },
    # code_18: deep_merge_dicts
    {
        "id": "code_18_mutant_1",
        "task_id": "code_18",
        "description": "Shallow overwrite on conflict instead of recursive deep merge",
        "code": '''
def deep_merge_dicts(d1: dict, d2: dict) -> dict:
    res = dict(d1)
    # Bug: shallow dict.update replaces nested dicts completely
    res.update(d2)
    return res
''',
    },
    {
        "id": "code_18_mutant_2",
        "task_id": "code_18",
        "description": "Returns empty dict if either operand is empty",
        "code": '''
def deep_merge_dicts(d1: dict, d2: dict) -> dict:
    if not d1 or not d2:
        return {}  # Bug: returns empty
    res = dict(d1)
    for k, v in d2.items():
        if k in res and isinstance(res[k], dict) and isinstance(v, dict):
            res[k] = deep_merge_dicts(res[k], v)
        else:
            res[k] = v
    return res
''',
    },
    # code_19: retry_with_backoff_simulator
    {
        "id": "code_19_mutant_1",
        "task_id": "code_19",
        "description": "Constant delay instead of exponential multiplier factor",
        "code": '''
def retry_with_backoff_simulator(target_attempt: int, max_retries: int, base_delay: float = 1.0, factor: float = 2.0):
    delays = []
    total = 0.0
    for attempt in range(1, max_retries + 1):
        if attempt == target_attempt:
            return (True, total, delays)
        d = base_delay  # Bug: does not multiply by factor
        delays.append(d)
        total += d
    return (False, total, delays)
''',
    },
    {
        "id": "code_19_mutant_2",
        "task_id": "code_19",
        "description": "Off-by-one retry count (allows max_retries + 1 attempts)",
        "code": '''
def retry_with_backoff_simulator(target_attempt: int, max_retries: int, base_delay: float = 1.0, factor: float = 2.0):
    delays = []
    total = 0.0
    # Bug: + 2 attempts allowed
    for attempt in range(1, max_retries + 2):
        if attempt == target_attempt:
            return (True, total, delays)
        d = base_delay * (factor ** (attempt - 1))
        delays.append(d)
        total += d
    return (False, total, delays)
''',
    },
    # code_20: evaluate_simple_expression
    {
        "id": "code_20_mutant_1",
        "task_id": "code_20",
        "description": "Left-to-right evaluation ignoring standard operator precedence",
        "code": '''
import re

def evaluate_simple_expression(expr: str) -> int:
    tokens = re.findall(r'\\d+|[+\\-*/]', expr.replace(" ", ""))
    if not tokens:
        return 0
    # Bug: strictly left-to-right evaluation
    val = int(tokens[0])
    i = 1
    while i < len(tokens):
        op = tokens[i]
        num = int(tokens[i+1])
        if op == '+': val += num
        elif op == '-': val -= num
        elif op == '*': val *= num
        elif op == '/': val //= num
        i += 2
    return val
''',
    },
    {
        "id": "code_20_mutant_2",
        "task_id": "code_20",
        "description": "Uses float division / without truncation instead of integer division //",
        "code": '''
def evaluate_simple_expression(expr: str) -> int:
    # Bug: eval with float division returns float
    val = eval(expr)  # Note: in real sandbox this might even be rejected
    return val
''',
    },
    # Extra mutants on raw-solvable tasks to reach 42 total mutants
    {
        "id": "code_01_mutant_3",
        "task_id": "code_01",
        "description": "Returns dict with row index as key instead of header mapping",
        "code": '''
def parse_simple_csv(csv_text: str):
    if not csv_text or not csv_text.strip():
        return []
    lines = [l for l in csv_text.splitlines() if l.strip()]
    if len(lines) <= 1:
        return []
    rows = []
    for line in lines[1:]:
        vals = [v.strip() for v in line.split(",")]
        rows.append({str(i): v for i, v in enumerate(vals)})
    return rows
''',
    },
    {
        "id": "code_08_mutant_3",
        "task_id": "code_08",
        "description": "Always returns max(nums) + 1 instead of first missing integer",
        "code": '''
def find_first_missing_positive(nums: list[int]) -> int:
    if not nums:
        return 1
    # Bug: returns max + 1, skipping holes
    pos = [x for x in nums if x > 0]
    return max(pos) + 1 if pos else 1
''',
    },
]
