# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Focused checks of the JSON profile, the RFC 3339 times and the RFC 8785 numbers in both verifiers.

restoration-evidence-00 Section 4.1 makes statements I-JSON (RFC 7493), canonicalized as in Section 4.1 of
agent-audit-record-03 with RFC 8785, without duplicate members, and its times RFC 3339 UTC times to whole
seconds. agent-audit-record-03 Sections 4.1.1 and 4.1.2 require RFC 8785, the I-JSON safe-integer bound, no
duplicate members and no nesting past 128 levels, and Section 4.3 makes every time an RFC 3339 date-time.
RFC 8785 Section 3.1 requires the input to be "adapted for I-JSON" and Section 5 has a verifier check that
the data "adheres to I-JSON" before the signature, so both verifiers refuse what RFC 7493 Section 2.1 bars:
surrogate code points and noncharacters in names and string values. A second 60 is accepted only where the
pinned leap-seconds.list records a leap second (RFC 3339 Section 5.7), and it orders and counts as its own
second. A time is compared by its instant and not by its spelling or a binary float: "Z", "z", "+00:00"
and "-00:00" name UTC (RFC 3339 Section 4.3), and a decimal fraction of any length keeps its exact value.
Python limits the digits int() converts from text (4300 by default since 3.11) and allows any limit from 640
upwards, or 0 for none. Every case below runs three times, under 640, under 4300 and with no limit, which
it sets for the duration of the case and restores after it, and expects the same result each time; the
lengths of the long cases are fixed and do not follow the limit. The verifiers never set the limit. The
delegation-root key set of a retained record is read with the reader of the Statement (agent-audit-record
Sections 4.6 and 4.7, reading L-ROOTMAT). Cases marked "RFC" below are taken from the text of the RFC named.
"""
import base64
import calendar
import hashlib
import importlib.util
import json
import os
import random
import struct
import sys
import time
from fractions import Fraction

import pytest

TOOLS = os.environ.get("AGENT_EVIDENCE_TOOLS") or os.path.join(os.path.dirname(__file__), "..", "tools")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TOOLS, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


A = _load("aar_verifier")
R = _load("rer_verifier")

# One digit more than int() converts under the default limit of Python 3.11, fixed, so the long cases have the
# same length under every limit below; under 640 they also cross the smallest limit Python allows.
LONG = 4301
# The smallest limit Python allows (sys.int_info.str_digits_check_threshold), the default, and none.
LIMITS = (640, 4300, 0)


@pytest.fixture(autouse=True, params=LIMITS, ids=lambda v: "int-limit-%d" % v)
def int_limit(request):
    """Every case under each of LIMITS, set for the case only and restored after it; the case expects the same
    result under each, and the verifiers must leave the limit as the case set it."""
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(request.param)
    try:
        yield request.param
        assert sys.get_int_max_str_digits() == request.param, "a verifier changed the limit"
    finally:
        sys.set_int_max_str_digits(before)


def _digits_oracle(d):
    """The value of a string of ASCII digits, one digit at a time, without any conversion of text to int, so
    the oracle holds under every limit and is independent of the verifiers' digits_value()."""
    v = 0
    for c in d:
        v = v * 10 + (ord(c) - 48)
    return v

# ECMAScript Number::toString of each double (RFC 8785 3.2.2.3), as printed by JSON.stringify in node 22
ES_NUMBERS = [
    (1e-7, "1e-7"), (1e-6, "0.000001"), (1.5e-7, "1.5e-7"), (1e21, "1e+21"),
    (1e20, "100000000000000000000"), (123.456, "123.456"), (-0.5, "-0.5"), (5e-324, "5e-324"),
    (1.7976931348623157e308, "1.7976931348623157e+308"), (0.30000000000000004, "0.30000000000000004"),
    (1e23, "1e+23"), (333333333.3333332, "333333333.3333332"), (4.35, "4.35"),
    (0.000001234, "0.000001234"), (-1e-7, "-1e-7"), (2.5e-5, "0.000025"), (1e300, "1e+300"),
    (123456789012345680000.0, "123456789012345680000"), (-0.0, "0"), (0.0, "0"),
]

NOT_JSON_PROFILE = [
    b'{"x":1e400}', b'{"x":-1e400}', b'{"x":1e-400}', b'{"x":9007199254740992}', b'{"x":1e16}',
    b'{"x":"\\ud800"}', b'{"x":"\\udc00a"}', b'{"\\ud800":1}', b'{"x":1,"x":2}',
    b'{"x":' + b"[" * 128 + b"]" * 128 + b"}",
]
# RFC 7493 2.1: noncharacters, escaped and as UTF-8, in a value and in a name; U+1FFFE and U+10FFFF as pairs
NONCHARACTERS = [b'{"x":"\\ufdd0"}', b'{"x":"\\ufdef"}', b'{"x":"\\uffff"}', b'{"\\ufffe":1}',
                 b'{"x":"\\ud83f\\udffe"}', b'{"x":"\\udbff\\udfff"}', '{"x":"a\ufdd0"}'.encode(),
                 '{"\U0010fffe":1}'.encode(), b'{"a":[{"b":"\\ufdd5"}]}', b'{"a":{"\\uffff":1}}']
NEAR_NONCHARACTERS = [b'{"x":"\\ufdcf"}', b'{"x":"\\ufdf0"}', b'{"x":"\\ufffd"}', b'{"x":"\\ud83f\\udffd"}',
                      '{"\U0010fffd":"\ue000"}'.encode()]
JSON_PROFILE_OK = NEAR_NONCHARACTERS + [b'{"x":1e-7}', b'{"x":"\\ud83d\\ude00"}', b'{"x":9007199254740991}', b'{"x":0e5}',
                   b'{"x":' + b"[" * 127 + b"]" * 127 + b"}"]

BAD_TIMES = ["1900-02-29T00:00:00Z", "2026-00-01T00:00:00Z", "2026-01-00T00:00:00Z", "2026-04-31T00:00:00Z",
             "2026-99-99T99:99:99Z", "2026-02-30T00:00:00Z", "2026-02-29T00:00:00Z", "2026-01-01T24:00:00Z",
             "2026-01-01T00:60:00Z", "2026-01-01T12:00:60Z", "2026-06-29T23:59:60Z", "2026-01-01T00:00:00Z\n",
             "٢٠٢٦-01-01T00:00:00Z", " 2026-01-01T00:00:00Z", "2026-1-01T00:00:00Z"]
# RFC 3339 1 ("between 0000AD and 9999AD"), 5.6 (date-fullyear = 4DIGIT; "t" and "z" may be lower case)
# and Appendix C (2000 and 0000 are leap years)
GOOD_UTC = ["2024-02-29T00:00:00Z", "2026-11-08T23:59:59Z", "2016-12-31T23:59:60Z", "2015-06-30T23:59:60Z",
            "1990-12-31T23:59:60Z", "2030-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "0000-02-29T12:00:00Z",
            "2000-02-29T00:00:00Z", "9999-12-31T23:59:59Z", "2026-11-08t12:00:00z", "2016-12-31t23:59:60z"]
# RFC 3339 5.7 and the pinned list: no leap second at these points, before 1972, after the last entry
# (2017-01-01) or after the expiry of the list (2027-06-28)
NO_LEAP = ["2026-02-28T23:59:60Z", "2016-06-30T23:59:60Z", "2016-12-30T23:59:60Z", "1971-12-31T23:59:60Z",
           "1972-03-31T23:59:60Z", "2018-12-31T23:59:60Z", "2026-06-30T23:59:60Z", "2026-12-31T23:59:60Z",
           "2027-06-30T23:59:60Z", "2030-12-31T23:59:60Z"]
# RFC 3339 Appendix D, the table "UTC Date  TAI - UTC After Leap Second", 1972-06-30 to 1998-12-31
RFC3339_TABLE = ["1972-06-30", "1972-12-31", "1973-12-31", "1974-12-31", "1975-12-31", "1976-12-31",
                 "1977-12-31", "1978-12-31", "1979-12-31", "1981-06-30", "1982-06-30", "1983-06-30",
                 "1985-06-30", "1987-12-31", "1989-12-31", "1990-12-31", "1992-06-30", "1993-06-30",
                 "1994-06-30", "1995-12-31", "1997-06-30", "1998-12-31"]


@pytest.mark.parametrize("value,text", ES_NUMBERS)
def test_rer_numbers_follow_rfc8785(value, text):
    assert R.jcs(value) == text.encode()


@pytest.mark.parametrize("value,text", ES_NUMBERS)
def test_aar_numbers_follow_rfc8785(value, text):
    assert A.jcs(value) == text.encode()


@pytest.mark.parametrize("raw", NOT_JSON_PROFILE + NONCHARACTERS)
def test_rer_refuses_what_i_json_refuses(raw):
    with pytest.raises(R.Rej) as e:
        R.parse(raw)
    assert e.value.code == "statement-malformed"


@pytest.mark.parametrize("raw", JSON_PROFILE_OK)
def test_rer_keeps_what_i_json_allows(raw):
    R.parse(raw)


@pytest.mark.parametrize("raw", NOT_JSON_PROFILE)
def test_aar_refuses_what_its_profile_refuses(raw):
    with pytest.raises(A.Fail):
        A.parse_profile(raw)


@pytest.mark.parametrize("raw", NONCHARACTERS)
def test_aar_refuses_noncharacters(raw):
    with pytest.raises(A.Fail) as e:
        A.parse_profile(raw)
    assert e.value.code == "not-i-json"


@pytest.mark.parametrize("raw", JSON_PROFILE_OK)
def test_aar_keeps_what_its_profile_allows(raw):
    A.parse_profile(raw)


# RFC 8259 6 puts no bound on the digits of a number, so these are JSON. The draft profile decides: an
# integer of 2^53 or more is refused as unsafe whatever its length, a value past the IEEE double range is
# refused, and a long mantissa or exponent that names a double is kept with that double (RFC 8785 3.2.2.3)
LONG_INTEGERS = [b'{"x":' + b"1" * LONG + b"}", b'{"x":-' + b"9" * LONG + b"}", b'{"x":1' + b"0" * LONG + b"}",
                 b'{"x":[' + b"7" * (3 * LONG) + b"]}"]
LONG_NUMBERS_OK = [(b'{"x":1e' + b"0" * LONG + b"1}", 10.0), (b'{"x":1e-' + b"0" * LONG + b"1}", 0.1),
                   (b'{"x":0.' + b"0" * LONG + b"1e" + str(LONG + 1).encode() + b"}", 1.0),
                   (b'{"x":1' + b"0" * LONG + b"e-" + str(LONG).encode() + b"}", 1.0),
                   (b'{"x":0.' + b"5" + b"0" * LONG + b"}", 0.5)]
LONG_NUMBERS_OUT = [b'{"x":' + b"1" * LONG + b".0}", b'{"x":1e' + b"9" * LONG + b"}",
                    b'{"x":1e-' + b"9" * LONG + b"}"]


@pytest.mark.parametrize("raw", LONG_INTEGERS)
def test_a_long_integer_is_unsafe_and_not_unparseable(raw):
    with pytest.raises(A.Fail) as e:
        A.parse_profile(raw)
    assert e.value.code == "unsafe-integer"
    with pytest.raises(R.Rej) as r:
        R.parse(raw)
    assert r.value.code == "statement-malformed" and "integer outside I-JSON" in r.value.text


@pytest.mark.parametrize("raw,value", LONG_NUMBERS_OK)
def test_a_long_mantissa_or_exponent_that_names_a_double_is_kept(raw, value):
    assert A.parse_profile(raw) == {"x": value} == R.parse(raw)


@pytest.mark.parametrize("raw", LONG_NUMBERS_OUT)
def test_a_long_number_outside_the_double_range_is_refused_by_its_rule(raw):
    with pytest.raises(A.Fail) as e:
        A.parse_profile(raw)
    assert e.value.code == "not-i-json"
    with pytest.raises(R.Rej) as r:
        R.parse(raw)
    assert r.value.code == "statement-malformed" and "IEEE 754" in r.value.text


# restoration-evidence-00 4.1 "UTC times to whole seconds": an offset other than UTC and any fraction are
# outside, and so is a numeric offset that is not 00:00
NOT_UTC_WHOLE = ["2026-01-01T00:00:00.5Z", "2026-01-01T01:00:00+01:00", "2016-12-31T23:59:59.5Z",
                 "1990-12-31T15:59:60-08:00", "2026-01-01T00:00:00+00:01", "2026-01-01T00:00:00-00:01",
                 "2026-01-01T00:00:00.0Z", "2026-01-01T00:00:00.000+00:00", "2026-01-01T00:00:00+0000",
                 "2026-01-01T00:00:00+00", "2016-12-31T23:59:60+00:60"]
# RFC 3339 4.3: "Z" and "+00:00" both name UTC, "-00:00" states the time in UTC (reading L-RLEAP)
UTC_OFFSETS = ["2017-01-01T00:00:00+00:00", "2017-01-01T00:00:00-00:00", "2016-12-31T23:59:60+00:00",
               "2016-12-31t23:59:60-00:00", "2026-11-08T12:00:00+00:00", "0000-01-01T00:00:00-00:00"]


@pytest.mark.parametrize("v", BAD_TIMES + NO_LEAP + NOT_UTC_WHOLE)
def test_rer_refuses_times_outside_rfc3339_utc_whole_seconds(v):
    with pytest.raises(R.Rej):
        R.tm(v, "issuedAt")


@pytest.mark.parametrize("v", GOOD_UTC + UTC_OFFSETS)
def test_rer_keeps_valid_times(v):
    assert R.tm(v, "issuedAt") == v


@pytest.mark.parametrize("off", ["+00:00", "-00:00", "z"])
def test_rer_takes_a_numeric_utc_offset_as_the_same_instant_as_z(off):
    # the example of the review: tm("2017-01-01T00:00:00+00:00", "probe") returns, and compares equal to Z
    v = "2017-01-01T00:00:00" + off
    assert R.tm(v, "probe") == v
    assert R.ts(v) == R.ts("2017-01-01T00:00:00Z") == A.t(v, "x")
    assert R.ts("2016-12-31T23:59:59Z") < R.ts("2016-12-31T23:59:60" + off) < R.ts(v)
    assert R.ts("2017-01-01T00:00:01" + off) > R.ts("2017-01-01T00:00:00Z")


def test_rer_compares_instants_in_the_type_rules():
    # 5.1 authorization-window-inverted and 5.5 revocation-outside-window take the instant, not the string:
    # with mixed spellings a string order would get both wrong
    a, b = "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00Z"
    assert not R.ts(a) > R.ts(b) and not R.ts(a) < R.ts(b)
    assert R.ts("2026-01-01T00:00:01-00:00") > R.ts("2026-01-01T00:00:00Z")
    assert R.ts("2026-01-01T00:00:00-00:00") < R.ts("2026-01-01T00:00:01Z")


@pytest.mark.parametrize("v", BAD_TIMES + NO_LEAP + ["2026-01-01T00:00:00+00:60", "2026-01-01T00:00:00+24:00",
                                                     "1990-12-31T16:59:60-08:00", "2026-02-28T15:59:60-08:00",
                                                     "2016-12-31T23:59:60.5+01:00"])
def test_aar_refuses_times_outside_rfc3339(v):
    with pytest.raises(A.Fail) as e:
        A.t(v, "issuedAt")
    assert e.value.code == "timestamp-malformed"


@pytest.mark.parametrize("v", GOOD_UTC + ["2026-01-01T00:00:00.5Z", "2026-01-01t01:00:00+01:00",
                                          "1990-12-31T15:59:60-08:00"])
def test_aar_keeps_valid_times(v):
    A.t(v, "issuedAt")


def test_round_trip_of_canonical_bytes():
    st = {"b": [1e-7, 2, "€"], "a": {"é": 1.5}}
    for m in (A, R):
        body = m.jcs(st)
        assert json.loads(body) == st
        assert body == b'{"a":{"\xc3\xa9":1.5},"b":[1e-7,2,"\xe2\x82\xac"]}'


# ---------------------------------------------------------------- leap seconds, RFC 3339 5.7 and 5.8


@pytest.mark.parametrize("day", RFC3339_TABLE)
def test_rfc3339_appendix_d_leap_seconds_are_accepted(day):
    assert R.tm(day + "T23:59:60Z", "issuedAt") == day + "T23:59:60Z"
    A.t(day + "T23:59:60Z", "issuedAt")


def test_the_example_of_rfc3339_5_8_is_one_instant():
    # RFC 3339 5.8: 1990-12-31T15:59:60-08:00 is "the same leap second in Pacific Standard Time"
    assert A.t("1990-12-31T15:59:60-08:00", "a") == A.t("1990-12-31T23:59:60Z", "b")


def test_a_leap_second_is_its_own_instant_in_order():
    seq = ["2016-12-31T23:59:59Z", "2016-12-31T23:59:59.5Z", "2016-12-31T23:59:60Z", "2016-12-31T23:59:60.5Z",
           "2017-01-01T00:00:00Z", "2017-01-01T00:59:60+01:00"]
    vals = [A.t(v, "x") for v in seq[:5]]
    assert vals == sorted(vals) and len(set(vals)) == 5
    assert A.t("2016-12-31T23:59:59.5Z", "a") < A.t("2016-12-31T23:59:60Z", "b")
    # the same leap second written at +01:00 is 00:59:60 local time and equals 23:59:60Z
    assert A.t(seq[5], "a") == A.t("2016-12-31T23:59:60Z", "b")
    whole = ["2016-12-31T23:59:59Z", "2016-12-31T23:59:60Z", "2017-01-01T00:00:00Z"]
    vals = [R.ts(R.tm(v, "x")) for v in whole]
    assert vals == sorted(vals) and len(set(vals)) == 3
    assert vals == [A.t(v, "x") for v in whole]


LEAP60 = "2016-12-31T23:59:60"


# the two pairs of the review: distinct instants a binary float collapsed into one value
FLOAT_PAIRS = [("2016-12-31T23:59:59.999999999Z", "2016-12-31T23:59:60Z"),
               ("2016-12-31T23:59:60.999999999Z", "2017-01-01T00:00:00Z")]


@pytest.mark.parametrize("earlier,later", FLOAT_PAIRS)
def test_aar_keeps_fractional_order_at_a_leap_second(earlier, later):
    a, b = A.t(earlier, "a"), A.t(later, "b")
    assert a < b and a != b
    assert b - a == Fraction(1, 10 ** 9)
    assert isinstance(a, Fraction) and isinstance(b, Fraction)


def test_aar_fractions_are_decimal_and_exact():
    # RFC 3339 5.6 time-secfrac = "." 1*DIGIT: every digit counts, trailing zeros add nothing
    base = A.t("2016-12-31T23:59:60Z", "x")
    assert A.t("2016-12-31T23:59:59." + "9" * 30 + "Z", "x") == base - Fraction(1, 10 ** 30)
    assert A.t("2016-12-31T23:59:60.000000000000Z", "x") == base
    assert A.t("2016-12-31T23:59:60.1Z", "x") - base == Fraction(1, 10)
    assert A.t("2017-01-01T00:59:59.999999999+01:00", "x") == A.t("2016-12-31T23:59:59.999999999Z", "y")


# RFC 3339 5.6 time-secfrac = "." 1*DIGIT has no upper bound. The three fractions of the review, each longer
# than int() converts by default, against their short spelling, their neighbours and by their exact distance


def test_aar_takes_a_long_fraction_as_its_short_spelling():
    long_one = A.t(LEAP60 + ".1" + "0" * (LONG - 1) + "Z", "x")
    assert long_one == A.t(LEAP60 + ".1Z", "y")
    assert long_one == A.t("2017-01-01T00:59:60.1" + "0" * LONG + "+01:00", "z")


def test_aar_orders_and_subtracts_a_fraction_of_nines_exactly():
    nines = A.t(LEAP60 + "." + "9" * LONG + "Z", "x")
    midnight, sixty = A.t("2017-01-01T00:00:00Z", "m"), A.t(LEAP60 + "Z", "s")
    assert sixty < nines < midnight
    assert midnight - nines == Fraction(1, 10 ** LONG)
    assert nines - A.t(LEAP60 + "." + "9" * (LONG - 1) + "Z", "y") == Fraction(9, 10 ** LONG)
    before = A.t("2016-12-31T23:59:59." + "9" * LONG + "Z", "b")
    assert before < sixty and sixty - before == Fraction(1, 10 ** LONG)


def test_aar_orders_and_subtracts_a_fraction_of_zeros_and_a_one_exactly():
    tiny = A.t(LEAP60 + "." + "0" * (LONG - 1) + "1Z", "x")
    sixty = A.t(LEAP60 + "Z", "s")
    assert sixty < tiny < A.t(LEAP60 + "." + "0" * (LONG - 2) + "1Z", "y")
    assert tiny - sixty == Fraction(1, 10 ** LONG)
    assert A.t(LEAP60 + "." + "0" * (3 * LONG) + "Z", "z") == sixty


def test_long_fractions_are_refused_by_rer_for_their_fraction_only():
    for v in (LEAP60 + ".1" + "0" * LONG + "Z", LEAP60 + "." + "9" * LONG + "Z", LEAP60 + "." + "0" * LONG + "Z"):
        with pytest.raises(R.Rej) as e:
            R.tm(v, "x")
        assert e.value.code == "predicate-malformed"


# Lengths just below, at and above each boundary of the conversion: one part (CHUNK), two parts, the smallest
# limit Python allows (640), the part size of the earlier fix (1000) and the default limit (4300)
BOUNDARY_LENGTHS = sorted({0, 1, 499, 500, 501, 639, 640, 641, 700, 999, 1000, 1001, 1999, 2000, 2001, 4299,
                           4300, 4301, 8601, 8602, 8603})


def test_each_int_call_stays_below_the_smallest_limit_python_allows():
    assert A.LEAP.CHUNK < sys.int_info.str_digits_check_threshold == 640


def test_digits_are_converted_without_the_interpreter_limit():
    rnd = random.Random(4300)
    for n in BOUNDARY_LENGTHS:
        for d in ("".join(rnd.choice("0123456789") for _ in range(n)), "9" * n, "1" + "0" * n):
            assert A.LEAP.digits_value(d) == _digits_oracle(d), n
            assert A.LEAP.integer("-" + d) == -_digits_oracle(d), n
    assert A.LEAP.digits_value("1" + "0" * (3 * LONG)) == 10 ** (3 * LONG)
    assert A.LEAP.digits_value("9" * LONG) == 10 ** LONG - 1
    assert A.LEAP.digits_value("0" * LONG + "7") == 7


def test_the_fraction_of_the_review_has_its_exact_value_under_every_limit():
    # the input of the review: 700 ones after 23:59:60, which int() refused under the limit 640
    v = A.t(LEAP60 + "." + "1" * 700 + "Z", "x")
    assert v - A.t(LEAP60 + "Z", "s") == Fraction((10 ** 700 - 1) // 9, 10 ** 700)


@pytest.mark.parametrize("n", [n for n in BOUNDARY_LENGTHS if n])
def test_fractions_at_each_boundary_length_have_their_exact_value(n):
    sixty, midnight = A.t(LEAP60 + "Z", "s"), A.t("2017-01-01T00:00:00Z", "m")
    ones = A.t(LEAP60 + "." + "1" * n + "Z", "x")
    assert ones - sixty == Fraction((10 ** n - 1) // 9, 10 ** n)
    nines = A.t(LEAP60 + "." + "9" * n + "Z", "y")
    assert sixty < ones < nines < midnight and midnight - nines == Fraction(1, 10 ** n)
    assert A.t(LEAP60 + "." + "0" * (n - 1) + "1Z", "z") - sixty == Fraction(1, 10 ** n)


@pytest.mark.parametrize("issued,sealed", FLOAT_PAIRS)
def test_aar_issuance_comparison_sees_an_issuedat_just_before_a_leap_sealedat(issued, sealed):
    # agent-audit-record 5.1 refuses issuance before sealedAt; the verifier compares t(issuedAt) <
    # t(sealedAt). The verdict itself is checked on the corpus records by the planted fault kinds
    # time:leap-order-ns-before-sixty and time:leap-order-ns-before-midnight of run_faults.py.
    assert A.t(issued, "issuedAt") < A.t(sealed, "sealedAt")
    assert not A.t(sealed, "issuedAt") < A.t(sealed, "sealedAt")


def test_elapsed_seconds_count_leap_seconds():
    assert A.t("2017-01-01T00:00:00Z", "a") - A.t("2016-12-31T23:59:59Z", "b") == 2
    assert A.t("2017-01-01T00:00:00Z", "a") - A.t("2016-12-31T23:59:60Z", "b") == 1
    assert A.t("2016-12-31T23:59:60Z", "a") - A.t("2016-12-31T23:59:59Z", "b") == 1
    # TAI-UTC went from 10 to 37 between the first and the last entry of the list
    assert A.t("2017-01-01T00:00:00Z", "a") - A.t("1972-01-01T00:00:00Z", "b") == 1483228800 - 63072000 + 27
    # after the last entry and after the expiry no further leap second is counted
    assert A.t("2030-01-01T00:00:00Z", "a") - A.t("2017-01-01T00:00:00Z", "b") == 1893456000 - 1483228800


def test_pinned_list_matches_rfc3339_table():
    L = A.LEAP
    for day in RFC3339_TABLE:
        p = calendar.timegm(time.strptime(day, "%Y-%m-%d")) + 86400
        assert L.inserted(p) and L.covered(p)
    assert len(L.STEPS) == 27 and all(s == 1 for _, s in L.STEPS)
    assert L.EXPIRES == calendar.timegm((2027, 6, 28, 0, 0, 0))
    assert R.LEAP.STEPS == L.STEPS


def test_list_is_refused_when_its_bytes_change(tmp_path):
    src = open(A.LEAP.PATH, "rb").read()
    bad = tmp_path / "leap-seconds.list"
    assert src.count(b"3692217600      37") == 1
    bad.write_bytes(src.replace(b"3692217600      37", b"3692217600      38"))
    with pytest.raises(RuntimeError, match="pin"):
        A.LEAP._load(str(bad))


def test_list_is_refused_when_its_own_hash_line_fails(tmp_path, monkeypatch):
    # with the SHA-256 pin moved to the changed bytes, the #h line of the file still refuses them
    src = open(A.LEAP.PATH, "rb").read()
    bad = tmp_path / "leap-seconds.list"
    bad.write_bytes(src.replace(b"3692217600      37", b"3692217600      38"))
    monkeypatch.setattr(A.LEAP, "SHA256", hashlib.sha256(bad.read_bytes()).hexdigest())
    with pytest.raises(RuntimeError, match="#h"):
        A.LEAP._load(str(bad))


def test_a_subtracted_leap_second_removes_23_59_59(monkeypatch):
    # RFC 3339 5.7: after a subtracted leap second the maximum of time-second is 58. The list holds none,
    # so a synthetic one at 2030-01-01 checks the branch.
    p = calendar.timegm((2030, 1, 1, 0, 0, 0))
    for m in (A, R):
        monkeypatch.setattr(m.LEAP, "_REMOVED", {p})
    with pytest.raises(A.Fail):
        A.t("2029-12-31T23:59:59Z", "x")
    with pytest.raises(R.Rej):
        R.tm("2029-12-31T23:59:59Z", "x")
    A.t("2029-12-31T23:59:58Z", "x")


# ---------------------------------------------------------------- RFC 8785, the samples of its own text

# RFC 8785 Appendix B, Table 1: IEEE 754 bits and the JSON representation (NaN and Infinity left out)
RFC8785_TABLE_1 = [
    ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,text", RFC8785_TABLE_1)
def test_numbers_follow_rfc8785_appendix_b(bits, text):
    v = struct.unpack(">d", bytes.fromhex(bits))[0]
    for m in (A, R):
        assert m.jcs(v) == text.encode()


def test_rfc8785_sorting_and_utf8_samples():
    # RFC 8785 3.2.3, the sorting sample, and 3.2.4, the bytes of the sample of 3.2.2 once canonicalized
    sample = json.loads('{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With '
                        'Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
                        '"\\u00f6":"Latin Small Letter O With Diaeresis"}')
    order = ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign",
             "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]
    expected = bytes.fromhex(
        "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72"
        "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a"
        "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31"
        "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37"
        "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30"
        "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d")
    data = json.loads('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
                      '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", '
                      '"literals": [null, true, false]}')
    for m in (A, R):
        body = m.jcs(sample).decode()
        assert [json.loads(body)[k] for k in json.loads(body)] == order
        assert m.jcs(data) == expected


def test_civil_seconds_match_the_calendar_module():
    rnd = random.Random(7)
    for _ in range(5000):
        y, m = rnd.randint(1, 9999), rnd.randint(1, 12)
        d = rnd.randint(1, calendar.monthrange(y, m)[1])
        hh, mi, ss = rnd.randint(0, 23), rnd.randint(0, 59), rnd.randint(0, 59)
        assert A.LEAP.posix(y, m, d, hh, mi, ss) == calendar.timegm((y, m, d, hh, mi, ss))
    # year 0000 is a leap year on the proleptic Gregorian calendar, 366 days before 0001-01-01
    assert A.LEAP.posix(1, 1, 1, 0, 0, 0) - A.LEAP.posix(0, 1, 1, 0, 0, 0) == 366 * 86400


def test_lower_case_t_and_z_compare_as_the_same_instant():
    assert A.t("2016-12-31t23:59:60z", "a") == A.t("2016-12-31T23:59:60Z", "b")
    assert R.ts(R.tm("2016-12-31t23:59:60z", "a")) == R.ts("2016-12-31T23:59:60Z")
    assert R.ts(R.tm("2016-12-31t23:59:59z", "a")) < R.ts(R.tm("2016-12-31T23:59:60Z", "b"))


# ---------------------------------------------------------------- one instant, every spelling


def _civil(p):
    """Civil UTC date and clock of POSIX second p on the proleptic Gregorian calendar, written here
    independently of the verifiers (days-to-civil, the inverse of the day count of RFC 3339 Appendix B)."""
    days, sec = divmod(p, 86400)
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    y = yoe + era * 400 + (m <= 2)
    return y, m, d, sec // 3600, sec // 60 % 60, sec % 60


LO, HI = calendar.timegm((1, 1, 1, 0, 0, 0)) - 366 * 86400, calendar.timegm((9999, 12, 31, 23, 59, 59))
UTC_ZONES = ("Z", "z", "+00:00", "-00:00")
LEAP_59 = [p - 1 for p, s in A.LEAP.STEPS if s == 1]  # the 23:59:59 UTC before each inserted leap second


def _instants(rnd, n):
    """n UTC instants as (p59, sixty, digits): the POSIX second of the clock with a second 60 read as 59,
    whether it is a second 60, and the decimal digits of the fraction. Their true order is the order of
    these tuples with the digits read as a decimal fraction, which needs no leap-second list."""
    out = []
    for _ in range(n):
        k = rnd.random()
        if k < 0.3:
            p, sixty = rnd.choice(LEAP_59), True
        elif k < 0.45:
            p, sixty = rnd.choice(LEAP_59) + rnd.choice((0, 1)), False
        else:
            p, sixty = rnd.randint(LO, HI), False
        n_dig = rnd.choice((0, 0, 1, 3, 6, 9, 9))
        digits = "".join(rnd.choice("0123456789") for _ in range(n_dig))
        if n_dig and rnd.random() < 0.2:
            digits = "9" * n_dig
        out.append((p, sixty, digits))
    return out


def _key(i):
    """The true order of instant i. Without trailing zeros, the digits of two fractions compare as strings in
    the order of their values, so no conversion to a number takes part, at any length."""
    p, sixty, digits = i
    return (p, sixty, digits.rstrip("0"))


def _spell(i, off_min, upper_t, zone, zeros):
    """One RFC 3339 spelling of instant i at an offset of off_min minutes; zone is the UTC designator
    used when off_min is 0 ("Z", "z", "+00:00" or "-00:00"), zeros the trailing zeros added to the fraction."""
    p, sixty, digits = i
    y, mo, d, hh, mi, ss = _civil(p + off_min * 60)
    if not 0 <= y <= 9999:
        return None
    frac = digits + "0" * zeros
    sec = "%02d" % (60 if sixty else ss)
    if off_min == 0:
        z = zone
    else:
        z = "%s%02d:%02d" % ("+" if off_min > 0 else "-", abs(off_min) // 60, abs(off_min) % 60)
    return "%04d-%02d-%02d%s%02d:%02d:%s%s%s" % (y, mo, d, "T" if upper_t else "t", hh, mi, sec,
                                                  "." + frac if frac else "", z)


def _spellings(rnd, i, n):
    out = []
    for zone in UTC_ZONES:
        out.append(_spell(i, 0, rnd.random() < 0.5, zone, 0))
    while len(out) < 4 + n:
        off = rnd.choice((0, rnd.randint(-(23 * 60 + 59), 23 * 60 + 59)))
        out.append(_spell(i, off, rnd.random() < 0.5, rnd.choice(UTC_ZONES),
                          rnd.choice((0, 0, 1, 4))))
    return [v for v in out if v is not None]


def _long_instants(rnd, n):
    """n instants with fractions longer than int() converts: nines, zeros and a one, or random digits."""
    out = []
    for p, sixty, _d in _instants(rnd, n):
        k = rnd.randint(LONG, 2 * LONG)
        digits = rnd.choice(("9" * k, "0" * (k - 1) + "1", "".join(rnd.choice("0123456789") for _ in range(k))))
        out.append((p, sixty, digits))
    return out


def test_sampled_spellings_of_random_instants_are_treated_alike_and_order_is_kept():
    # A sample, not every spelling: 4000 random instants and 200 with fractions longer than int() converts,
    # each written in the four UTC spellings and six more drawn at random (offset, case, trailing zeros)
    rnd = random.Random(20261108)
    inst = _instants(rnd, 4000) + _long_instants(random.Random(4301), 200)
    seen = []
    for i in inst:
        sp = _spellings(rnd, i, 6)
        assert len(sp) >= 4
        # agent-audit-record 4.3: any RFC 3339 date-time; every spelling gives one exact value
        vals = {A.t(v, "x") for v in sp}
        assert len(vals) == 1, sp
        a = vals.pop()
        # restoration evidence 4.1: UTC to whole seconds; the UTC spellings without a fraction are taken,
        # give one value and the same value as agent-audit-record; every other sampled spelling is refused
        for v in sp:
            if v[19:] in UTC_ZONES:  # nothing between the seconds and a UTC designator
                assert R.tm(v, "x") == v and R.ts(v) == a, v
            else:
                with pytest.raises(R.Rej):
                    R.tm(v, "x")
        seen.append((_key(i), a, sp[0], sp[0][19:] in UTC_ZONES))
    # order: two distinct instants keep their order under every verifier, equal ones compare equal
    seen.sort(key=lambda x: x[0])
    for (k1, a1, v1, w1), (k2, a2, v2, w2) in zip(seen, seen[1:]):
        assert (a1 < a2) if k1 < k2 else (a1 == a2), (v1, v2)
        if w1 and w2:
            assert (R.ts(v1) < R.ts(v2)) if k1 < k2 else (R.ts(v1) == R.ts(v2))
    # random pairs, not only neighbours
    for _ in range(4000):
        (k1, a1, _v1, _w1), (k2, a2, _v2, _w2) = rnd.sample(seen, 2)
        assert (a1 < a2) == (k1 < k2) and (a1 == a2) == (k1 == k2)


# ---------------------------------------------------------------- the delegation-root key set, 4.6 and 4.7

def _retained_with_root(material):
    """A retained record whose entry carries material as its delegation-root element and whose payload names its
    digest as delegation.rootDigest; the payload is a bare predicate, so the record itself is malformed, which
    4.6 keeps beside the dating result: the entry is checked on its own. No anchor, not received."""
    H = A.hfun("sha256")
    st = {"predicate": {"hashAlgorithm": "sha256", "issuedAt": "2026-09-19T11:04:00Z",
                        "delegation": {"rootDigest": H(material)}}}
    env = {"payload": base64.b64encode(A.jcs(st)).decode(), "payloadType": A.PAYLOAD_TYPE,
           "signatures": [{"keyid": "k", "sig": base64.b64encode(b"\x00" * 64).decode()}]}
    ent = {"envelopeDigest": H(A.jcs(env)), "received": False, "anchorWithin": 300, "anchors": [],
           "validationData": [{"for": "delegation-root", "mediaType": "application/jwk-set+json",
                               "value": base64.b64encode(material).decode()}]}
    return {"envelope": env, "retention": ent}


ROOT_KEY = b'{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'


def _with_member(lit):
    return ROOT_KEY[:-1] + b',"unused":' + lit + b"}"


# A key set under the profile of 4.1 keeps the root established, also with an unused safe number
ROOT_OK = [(ROOT_KEY, "Ed25519"), (_with_member(b"7"), "Ed25519"), (_with_member(b"-9007199254740991"), "Ed25519"),
           (_with_member(b"0." + b"5" * LONG), "Ed25519"),
           (b'{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]}', "ECDSA-P-256")]
# Outside the profile of 4.1, or not a key set: unreadable, the root not established, the same under every limit.
# The first four are the number of the review (4301 digits) and its signed neighbour, and the same at 700
# digits, which a plain json.loads() refuses under the limit 640
ROOT_BAD = [_with_member(b"1" * LONG), _with_member(b"-" + b"1" * LONG), _with_member(b"1" * 700),
            _with_member(b"-" + b"1" * 700), _with_member(b"9007199254740992"), _with_member(b"1e400"),
            _with_member(b"1" * LONG + b".0"), _with_member(b'"\\ud800"'),
            ROOT_KEY[:-1] + b',"keys":[]}', b'{"keys":[]}', b'{"keys":[1]}', b'{"keys":[{"crv":"Ed25519"}]}',
            b'{"keys":[{"kty":"OKP"}]}', b"[]", b"not json", b"\xff"]


@pytest.mark.parametrize("material,alg", ROOT_OK)
def test_a_delegation_root_key_set_under_the_profile_is_established(material, alg):
    _rec, dat = A.check_retained(_retained_with_root(material), {}, {})
    assert dat["entry"] == "well-formed", dat
    assert dat["delegationRoot"] == {"result": "established", "algorithm": alg}


@pytest.mark.parametrize("material", ROOT_BAD)
def test_a_delegation_root_key_set_outside_the_profile_is_unreadable(material):
    _rec, dat = A.check_retained(_retained_with_root(material), {}, {})
    assert dat["entry"] == "malformed"
    assert dat["failure"]["code"] == "entry-delegation-root-unreadable", dat["failure"]
    assert dat["delegationRoot"] == {"result": "not-established"}


def test_the_long_number_of_the_review_is_refused_by_its_rule_not_by_the_limit():
    for lit, code in ((b"1" * LONG, "unsafe-integer"), (b"-" + b"1" * LONG, "unsafe-integer"),
                      (b"1e400", "not-i-json")):
        _rec, dat = A.check_retained(_retained_with_root(_with_member(lit)), {}, {})
        assert dat["failure"]["text"].endswith(code), dat["failure"]
