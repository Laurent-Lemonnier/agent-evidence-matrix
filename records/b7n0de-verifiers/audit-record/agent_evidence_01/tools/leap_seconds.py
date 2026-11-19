# Copyright 2026 Konrad Gruszka
# Licensed under the Apache License, Version 2.0; see LICENSE.
"""Leap seconds from the pinned IERS/IANA leap-seconds.list, for the RFC 3339 times of both verifiers.

RFC 3339 Section 5.7 lets time-second be 60 only "at the end of months in which a leap second occurs"
and shifts that point by the zone offset; it also allows a subtracted leap second, after which the
maximum second is 58. Which months those are is not in RFC 3339. This module reads it from the pinned
leap-seconds.list next to this directory, refuses any other bytes (SHA-256 and the file's own #h line),
and offers three things:

- inserted(p): whether a positive leap second ends at POSIX second p, i.e. 23:59:60 UTC is the second
  before the UTC midnight p;
- removed(p): whether a negative leap second ends at p, so that 23:59:59 UTC before p does not exist;
- elapsed(p): p plus the leap seconds that took effect at or before p. Differences of elapsed values are
  elapsed SI seconds, and a second 60 maps to elapsed(p_59) + 1, after 23:59:59 and before the midnight;
- instant(p, sixty, digits): the exact instant of a parsed time as a Fraction of elapsed seconds, with the
  digits of time-secfrac taken as a decimal fraction and never as a binary float, so that two times are
  equal exactly when they name the same instant and ordered exactly as their instants. RFC 3339 5.6
  puts no bound on the number of digits, and digits_value() converts them in parts below the smallest
  limit on integer string conversion the interpreter allows (640 digits), so a fraction of any length
  names its instant under every limit;
- check(path): the reason the list at path is refused, or None, for a runner that checks the list before
  anything else and reports a failed pin with its own exit code.

After the last entry and up to the expiry date of the list, the list is authoritative: no further leap
second occurred. For an instant at or after the expiry, a second 60 cannot be confirmed and is refused
(covered() is false), and seconds 00 to 59 count with the leap seconds of the list only.

date_exists() and posix() cover the full range of RFC 3339, years 0000 to 9999 (Section 1, "between
0000AD and 9999AD", and date-fullyear = 4DIGIT in Section 5.6), on the Gregorian calendar with the
leap-year rule of Appendix C and the month lengths of Section 5.7.
"""
import hashlib
import os
from fractions import Fraction

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "leap-seconds.list")
SHA256 = "db5a895f16853b03bfc865e8d68f9fc8710ef1740e3400c701cd46a5bbbc3433"
NTP_TO_POSIX = 2208988800  # seconds from 1900-01-01 to 1970-01-01


def _load(path=PATH):
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError("leap-seconds.list does not match its pin")
    digits, h, updated, expires, rows = "", None, None, None, []
    for line in raw.decode("ascii").splitlines():
        if line.startswith("#$"):
            updated = line[2:].split()[0]
            digits += updated
        elif line.startswith("#@"):
            expires = line[2:].split()[0]
            digits += expires
        elif line.startswith("#h"):
            h = "".join(line[2:].split())
        elif line and not line.startswith("#"):
            ntp, dtai = line.split("#")[0].split()[:2]
            digits += ntp + dtai
            rows.append((int(ntp) - NTP_TO_POSIX, int(dtai)))
    if h is None or hashlib.sha1(digits.encode("ascii")).hexdigest() != h:
        raise RuntimeError("leap-seconds.list fails its own #h check")
    # The first row sets TAI-UTC at 1972-01-01 and is not a leap second; each later row is one.
    steps = [(p, d - rows[i][1]) for i, (p, d) in enumerate(rows[1:])]
    if any(s not in (1, -1) for _, s in steps):
        raise RuntimeError("leap-seconds.list holds a step other than one second")
    return steps, int(expires) - NTP_TO_POSIX


def check(path=PATH):
    """The reason the list at path is refused (pin, own #h line, unreadable or malformed), or None."""
    try:
        _load(path)
    except (OSError, UnicodeDecodeError, ValueError, IndexError, TypeError, RuntimeError) as e:
        return "%s: %s" % (type(e).__name__, e)
    return None


STEPS, EXPIRES = _load()
_INSERTED = {p for p, s in STEPS if s == 1}
_REMOVED = {p for p, s in STEPS if s == -1}


def covered(p):
    """Whether the list speaks for the UTC second that ends at POSIX second p."""
    return p <= EXPIRES


def inserted(p):
    return p in _INSERTED


def removed(p):
    return p in _REMOVED


def elapsed(p):
    return p + sum(s for q, s in STEPS if q <= p)


# Digits converted by one int() call. Python accepts any limit on integer string conversion from 640 digits
# upwards (sys.int_info.str_digits_check_threshold) and 0 for none, so every call stays below the smallest
# limit that can be in force, whatever limit a caller has set; the limit itself is never changed.
CHUNK = 500


def digits_value(s):
    """The integer value of a string of ASCII digits of any length.

    int() refuses text of more than sys.get_int_max_str_digits() digits, which may be any value from 640
    upwards. The digits are split in halves until each part has at most CHUNK of them, below 640, and the
    parts are joined with powers of ten, which involves no string conversion, so the result is the same
    under every limit and the limit is left as it is.
    """
    if len(s) <= CHUNK:
        return int(s) if s else 0
    h = len(s) // 2
    return digits_value(s[:h]) * 10 ** (len(s) - h) + digits_value(s[h:])


def integer(s):
    """The value of an optionally signed JSON integer literal of any length, through digits_value()."""
    return -digits_value(s[1:]) if s.startswith("-") else digits_value(s)


def instant(p, sixty=False, digits=""):
    """Exact elapsed seconds of a time whose clock reads POSIX second p in UTC, a second 60 read as 59.

    sixty marks a second 60 (one second after p), digits are the decimal digits of time-secfrac without
    the dot. RFC 3339 5.6 allows any number of them; each digit counts, a trailing zero adds nothing and is
    dropped before the conversion.
    """
    whole = Fraction(elapsed(p) + (1 if sixty else 0))
    digits = digits.rstrip("0")
    return whole + Fraction(digits_value(digits), 10 ** len(digits)) if digits else whole


def date_exists(y, m, d):
    if not 1 <= m <= 12 or d < 1:
        return False
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)  # RFC 3339 Appendix C
    return d <= (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[m - 1]


def posix(y, m, d, hh, mi, ss):
    """Seconds from 1970-01-01T00:00:00 to the given civil time on the proleptic Gregorian calendar."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return (era * 146097 + doe - 719468) * 86400 + hh * 3600 + mi * 60 + ss
