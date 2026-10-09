"""
Mutant Benchmark for Holdout Coding Tasks (code_21 - code_30)
Contains 20 realistic buggy implementations (mutants), 2 per task.
Every mutant MUST fail the hidden reference test suite in test_coding_tasks_holdout.py.
Pre-declared decision rule: The gate must accept strictly 0 mutants (100% kill rate).
"""

from typing import Any, Dict, List

MUTANTS_HOLDOUT: List[Dict[str, Any]] = [
    # code_21: group_anagrams
    {
        "id": "code_21_mutant_1",
        "task_id": "code_21",
        "description": "Fails to sort tie-sized anagram groups lexicographically",
        "code": '''
def group_anagrams(words: list[str]) -> list[list[str]]:
    if not words:
        return []
    groups = {}
    for w in words:
        k = "".join(sorted(w))
        groups.setdefault(k, []).append(w)
    # Bug: only sorts by length descending, forgets tie-breaking by first word
    res = list(groups.values())
    res.sort(key=lambda g: len(g), reverse=True)
    return res
''',
    },
    {
        "id": "code_21_mutant_2",
        "task_id": "code_21",
        "description": "Sorts words inside groups alphabetically instead of preserving first-appearance order",
        "code": '''
def group_anagrams(words: list[str]) -> list[list[str]]:
    if not words:
        return []
    groups = {}
    for w in words:
        k = "".join(sorted(w))
        groups.setdefault(k, []).append(w)
    # Bug: sorts elements inside each group
    res = [sorted(g) for g in groups.values()]
    res.sort(key=lambda g: (-len(g), g[0] if g else ""))
    return res
''',
    },
    # code_22: merge_intervals
    {
        "id": "code_22_mutant_1",
        "task_id": "code_22",
        "description": "Fails to merge touching intervals where start == end",
        "code": '''
def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals, key=lambda x: x[0])
    merged = [intervals[0]]
    for s, e in intervals[1:]:
        prev_s, prev_e = merged[-1]
        # Bug: uses strict < instead of <=, missing touching intervals
        if s < prev_e:
            merged[-1] = (prev_s, max(prev_e, e))
        else:
            merged.append((s, e))
    return merged
''',
    },
    {
        "id": "code_22_mutant_2",
        "task_id": "code_22",
        "description": "Fails to sort input intervals by start before merging",
        "code": '''
def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    # Bug: does not sort intervals first
    merged = [intervals[0]]
    for s, e in intervals[1:]:
        prev_s, prev_e = merged[-1]
        if s <= prev_e:
            merged[-1] = (prev_s, max(prev_e, e))
        else:
            merged.append((s, e))
    return merged
''',
    },
    # code_23: parse_query_string
    {
        "id": "code_23_mutant_1",
        "task_id": "code_23",
        "description": "Fails to decode '+' as spaces in query values",
        "code": '''
import urllib.parse

def parse_query_string(query: str) -> dict[str, list[str]]:
    if not query:
        return {}
    if query.startswith("?"):
        query = query[1:]
    res = {}
    for part in query.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        # Bug: unquote instead of unquote_plus (+ remains +)
        dec_k = urllib.parse.unquote(k)
        dec_v = urllib.parse.unquote(v)
        res.setdefault(dec_k, []).append(dec_v)
    return res
''',
    },
    {
        "id": "code_23_mutant_2",
        "task_id": "code_23",
        "description": "Omits parameters that do not have an '=' sign",
        "code": '''
import urllib.parse

def parse_query_string(query: str) -> dict[str, list[str]]:
    if not query:
        return {}
    if query.startswith("?"):
        query = query[1:]
    res = {}
    for part in query.split("&"):
        if not part or "=" not in part:
            # Bug: drops keys without '='
            continue
        k, v = part.split("=", 1)
        dec_k = urllib.parse.unquote_plus(k)
        dec_v = urllib.parse.unquote_plus(v)
        res.setdefault(dec_k, []).append(dec_v)
    return res
''',
    },
    # code_24: flatten_nested_dict
    {
        "id": "code_24_mutant_1",
        "task_id": "code_24",
        "description": "Drops empty nested dictionaries instead of preserving them",
        "code": '''
def flatten_nested_dict(d: dict, sep: str = ".") -> dict:
    res = {}
    def _flatten(obj, prefix=""):
        if isinstance(obj, dict):
            # Bug: if obj is empty dict, nothing is recorded
            for k, v in obj.items():
                p = f"{prefix}{sep}{k}" if prefix else str(k)
                _flatten(v, p)
        else:
            res[prefix] = obj
    _flatten(d)
    return res
''',
    },
    {
        "id": "code_24_mutant_2",
        "task_id": "code_24",
        "description": "Flattens only 1 level deep, leaving deeper nested dictionaries unflattened",
        "code": '''
def flatten_nested_dict(d: dict, sep: str = ".") -> dict:
    if not d:
        return {}
    res = {}
    for k, v in d.items():
        if isinstance(v, dict):
            # Bug: only flattens one level
            for sub_k, sub_v in v.items():
                res[f"{k}{sep}{sub_k}"] = sub_v
        else:
            res[k] = v
    return res
''',
    },
    # code_25: tokenize_arithmetic
    {
        "id": "code_25_mutant_1",
        "task_id": "code_25",
        "description": "Always treats '-' as a standalone operator rather than negative sign",
        "code": '''
def tokenize_arithmetic(expr: str) -> list[str]:
    tokens = []
    i = 0
    s = "".join(expr.split())
    while i < len(s):
        ch = s[i]
        if ch in "+-*/%()":
            tokens.append(ch)
            i += 1
        elif ch.isdigit():
            j = i
            while j < len(s) and s[j].isdigit():
                j += 1
            tokens.append(s[i:j])
            i = j
        else:
            i += 1
    return tokens
''',
    },
    {
        "id": "code_25_mutant_2",
        "task_id": "code_25",
        "description": "Fails to recognize unary minus after '(' parenthesis",
        "code": '''
def tokenize_arithmetic(expr: str) -> list[str]:
    tokens = []
    i = 0
    s = "".join(expr.split())
    while i < len(s):
        ch = s[i]
        if ch == "-" and i + 1 < len(s) and s[i+1].isdigit():
            # Bug: only checks start of expr or operator, misses '('
            if not tokens or tokens[-1] in "+-*/%":
                j = i + 1
                while j < len(s) and s[j].isdigit():
                    j += 1
                tokens.append(s[i:j])
                i = j
                continue
        if ch in "+-*/%()":
            tokens.append(ch)
            i += 1
        elif ch.isdigit():
            j = i
            while j < len(s) and s[j].isdigit():
                j += 1
            tokens.append(s[i:j])
            i = j
        else:
            i += 1
    return tokens
''',
    },
    # code_26: validate_credit_card
    {
        "id": "code_26_mutant_1",
        "task_id": "code_26",
        "description": "Omits digit doubling in Luhn check (sums raw digits)",
        "code": '''
def validate_credit_card(number: str) -> dict:
    cleaned = "".join(c for c in number if c not in " -")
    if not cleaned.isdigit() or not (13 <= len(cleaned) <= 19):
        return {"valid": False, "brand": "Unknown"}
    # Bug: does not double alternate digits
    total = sum(int(c) for c in cleaned)
    valid = (total % 10 == 0)
    brand = "Unknown"
    if cleaned.startswith("4"):
        brand = "Visa"
    elif any(cleaned.startswith(p) for p in ("51", "52", "53", "54", "55")):
        brand = "Mastercard"
    elif cleaned.startswith("34") or cleaned.startswith("37"):
        brand = "Amex"
    return {"valid": valid, "brand": brand}
''',
    },
    {
        "id": "code_26_mutant_2",
        "task_id": "code_26",
        "description": "Fails to subtract 9 when doubled digit exceeds 9 in Luhn check",
        "code": '''
def validate_credit_card(number: str) -> dict:
    cleaned = "".join(c for c in number if c not in " -")
    if not cleaned.isdigit() or not (13 <= len(cleaned) <= 19):
        return {"valid": False, "brand": "Unknown"}
    digits = [int(c) for c in cleaned]
    total = 0
    for idx, d in enumerate(reversed(digits)):
        if idx % 2 == 1:
            # Bug: misses subtracting 9 if doubled > 9
            total += d * 2
        else:
            total += d
    valid = (total % 10 == 0)
    brand = "Unknown"
    if cleaned.startswith("4"):
        brand = "Visa"
    elif any(cleaned.startswith(p) for p in ("51", "52", "53", "54", "55")):
        brand = "Mastercard"
    elif cleaned.startswith("34") or cleaned.startswith("37"):
        brand = "Amex"
    return {"valid": valid, "brand": brand}
''',
    },
    # code_27: word_wrap_text
    {
        "id": "code_27_mutant_1",
        "task_id": "code_27",
        "description": "Hard-splits words longer than width instead of keeping them whole on a line",
        "code": '''
def word_wrap_text(text: str, width: int) -> str:
    if not text:
        return ""
    words = text.split()
    if not words:
        return ""
    lines = []
    cur_line = []
    cur_len = 0
    for w in words:
        # Bug: forcefully chops long words into chunks
        if len(w) > width:
            if cur_line:
                lines.append(" ".join(cur_line))
                cur_line, cur_len = [], 0
            for k in range(0, len(w), width):
                lines.append(w[k:k+width])
            continue
        if cur_len + len(w) + (1 if cur_line else 0) <= width:
            cur_line.append(w)
            cur_len += len(w) + (1 if len(cur_line) > 1 else 0)
        else:
            lines.append(" ".join(cur_line))
            cur_line = [w]
            cur_len = len(w)
    if cur_line:
        lines.append(" ".join(cur_line))
    return "\\n".join(lines)
''',
    },
    {
        "id": "code_27_mutant_2",
        "task_id": "code_27",
        "description": "Prematurely wraps lines due to strict < check",
        "code": '''
def word_wrap_text(text: str, width: int) -> str:
    if not text:
        return ""
    words = text.split()
    if not words:
        return ""
    lines = []
    cur_line = []
    cur_len = 0
    for w in words:
        needed = len(w) + (1 if cur_line else 0)
        # Bug: uses strict < so an exact-width line gets wrapped
        if cur_len + needed < width:
            cur_line.append(w)
            cur_len += needed
        else:
            if cur_line:
                lines.append(" ".join(cur_line))
            cur_line = [w]
            cur_len = len(w)
    if cur_line:
        lines.append(" ".join(cur_line))
    return "\\n".join(lines)
''',
    },
    # code_28: levenshtein_distance
    {
        "id": "code_28_mutant_1",
        "task_id": "code_28",
        "description": "Calculates difference in string lengths instead of Levenshtein edit distance",
        "code": '''
def levenshtein_distance(s1: str, s2: str) -> int:
    # Bug: naive length difference
    return abs(len(s1) - len(s2))
''',
    },
    {
        "id": "code_28_mutant_2",
        "task_id": "code_28",
        "description": "Always adds substitution cost even when characters are equal",
        "code": '''
def levenshtein_distance(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            # Bug: always charges 1 for substitution
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + 1,
            )
    return dp[m][n]
''',
    },
    # code_29: longest_common_prefix
    {
        "id": "code_29_mutant_1",
        "task_id": "code_29",
        "description": "Unchecked index access causes IndexError on empty input list",
        "code": '''
def longest_common_prefix(strs: list[str]) -> str:
    # Bug: does not check if strs is empty
    prefix = strs[0]
    for s in strs[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
    return prefix
''',
    },
    {
        "id": "code_29_mutant_2",
        "task_id": "code_29",
        "description": "Only checks prefix between first two elements, ignoring subsequent elements",
        "code": '''
def longest_common_prefix(strs: list[str]) -> str:
    if not strs:
        return ""
    if len(strs) == 1:
        return strs[0]
    # Bug: only compares strs[0] and strs[1]
    s1, s2 = strs[0], strs[1]
    prefix = ""
    for c1, c2 in zip(s1, s2):
        if c1 == c2:
            prefix += c1
        else:
            break
    return prefix
''',
    },
    # code_30: compress_string_rle
    {
        "id": "code_30_mutant_1",
        "task_id": "code_30",
        "description": "Includes count '1' even when run length is 1 (e.g. 'a1b1' instead of 'ab')",
        "code": '''
def compress_string_rle(s: str) -> str:
    if not s:
        return ""
    res = []
    i = 0
    while i < len(s):
        char = s[i]
        count = 0
        while i < len(s) and s[i] == char:
            count += 1
            i += 1
        # Bug: always appends count
        res.append(f"{char}{count}")
    return "".join(res)
''',
    },
    {
        "id": "code_30_mutant_2",
        "task_id": "code_30",
        "description": "Fails to append the last run if it has count 1",
        "code": '''
def compress_string_rle(s: str) -> str:
    if not s:
        return ""
    res = []
    i = 0
    while i < len(s):
        char = s[i]
        count = 0
        while i < len(s) and s[i] == char:
            count += 1
            i += 1
        # Bug: drops count 1 characters entirely
        if count > 1:
            res.append(f"{char}{count}")
    return "".join(res)
''',
    },
]
