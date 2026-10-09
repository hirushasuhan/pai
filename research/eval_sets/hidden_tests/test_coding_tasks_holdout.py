"""
Hidden Unit Tests for Holdout Coding Tasks (code_21 - code_30)
Kept strictly isolated in this file; NEVER shown to models during evaluation.
Contains 4-5 rigorous assertions per task testing edge cases, boundaries, and negative cases.
"""

from typing import Any, Callable, Dict, List


HIDDEN_TESTS_HOLDOUT: Dict[str, List[Callable[[Any], bool]]] = {
    "code_21": [  # group_anagrams
        lambda f: f([]) == [],
        lambda f: f(["a"]) == [["a"]],
        lambda f: f(["eat", "tea", "tan", "ate", "nat", "bat"]) == [["eat", "tea", "ate"], ["tan", "nat"], ["bat"]],
        lambda f: f(["cab", "tin", "pew", "duh", "may", "ill", "buy", "bar", "max", "doc"]) == [
            ["bar"], ["buy"], ["cab"], ["doc"], ["duh"], ["ill"], ["max"], ["may"], ["pew"], ["tin"]
        ],
    ],
    "code_22": [  # merge_intervals
        lambda f: f([]) == [],
        lambda f: f([(1, 4), (4, 5)]) == [(1, 5)],
        lambda f: f([(1, 3), (2, 6), (8, 10), (15, 18)]) == [(1, 6), (8, 10), (15, 18)],
        lambda f: f([(1, 4), (2, 3)]) == [(1, 4)],
        lambda f: f([(5, 7), (1, 3)]) == [(1, 3), (5, 7)],
    ],
    "code_23": [  # parse_query_string
        lambda f: f("") == {},
        lambda f: f("?name=Alice&tag=admin&tag=user&flag") == {"name": ["Alice"], "tag": ["admin", "user"], "flag": [""]},
        lambda f: f("?search=hello+world%21") == {"search": ["hello world!"]},
        lambda f: f("a=1&&b=2") == {"a": ["1"], "b": ["2"]},
    ],
    "code_24": [  # flatten_nested_dict
        lambda f: f({}) == {},
        lambda f: f({"a": 1, "b": 2}) == {"a": 1, "b": 2},
        lambda f: f({"user": {"name": "Alice", "address": {"city": "Colombo"}}, "active": True}) == {
            "user.name": "Alice",
            "user.address.city": "Colombo",
            "active": True,
        },
        lambda f: f({"x": {"y": {}}}) == {"x.y": {}},
    ],
    "code_25": [  # tokenize_arithmetic
        lambda f: f("3 + 4 * 2 / (1 - 5)") == ["3", "+", "4", "*", "2", "/", "(", "1", "-", "5", ")"],
        lambda f: f("-5 + 10") == ["-5", "+", "10"],
        lambda f: f("2 * -3") == ["2", "*", "-3"],
        lambda f: f("(-10)") == ["(", "-10", ")"],
    ],
    "code_26": [  # validate_credit_card
        lambda f: f("4532 0151 1283 036") == {"valid": True, "brand": "Visa"},
        lambda f: f("5105 1051 0510 5100") == {"valid": True, "brand": "Mastercard"},
        lambda f: f("3782 822463 10005") == {"valid": True, "brand": "Amex"},
        lambda f: f("1234 5678 9012 3456")["valid"] is False,
        lambda f: f("invalid-card") == {"valid": False, "brand": "Unknown"},
    ],
    "code_27": [  # word_wrap_text
        lambda f: f("The quick brown fox jumps over the lazy dog", 15) == "The quick brown\nfox jumps over\nthe lazy dog",
        lambda f: f("Hello World", 20) == "Hello World",
        lambda f: f("Supercalifragilisticexpialidocious is long", 10) == "Supercalifragilisticexpialidocious\nis long",
        lambda f: f("", 10) == "",
    ],
    "code_28": [  # levenshtein_distance
        lambda f: f("kitten", "sitting") == 3,
        lambda f: f("flaw", "lawn") == 2,
        lambda f: f("", "abc") == 3,
        lambda f: f("abc", "abc") == 0,
        lambda f: f("intention", "execution") == 5,
    ],
    "code_29": [  # longest_common_prefix
        lambda f: f([]) == "",
        lambda f: f(["flower", "flow", "flight"]) == "fl",
        lambda f: f(["dog", "racecar", "car"]) == "",
        lambda f: f(["interspecies", "interstellar", "interstate"]) == "inters",
        lambda f: f(["single"]) == "single",
    ],
    "code_30": [  # compress_string_rle
        lambda f: f("") == "",
        lambda f: f("aaabbc") == "a3b2c",
        lambda f: f("abcd") == "abcd",
        lambda f: f("a" * 10) == "a10",
        lambda f: f("abbcccddddeeeee") == "ab2c3d4e5",
    ],
}
