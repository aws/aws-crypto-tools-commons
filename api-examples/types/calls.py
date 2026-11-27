"""Count the calls a customer writes to pass a value. The types page sorts each type by this count.

Each function or method call, `new`, `await`, cast like `(long)`, function literal (`=>`) and extra
line counts as one. `&`, `Some(...)` and literals like `[x]` don't count, because they are not conversions.
"""
import re

# A name right before "(", not after "new ", which counts on its own.
CALL = re.compile(r"(?<!new )\b([A-Za-z_]\w*)\s*\(")
OTHER = [re.compile(r"\bnew\s+[A-Za-z_]"), re.compile(r"\bawait\b"), re.compile(r"=>"),
         re.compile(r"\(\s*(long|int|uint|ulong|short|ushort|byte|sbyte|double|float|decimal)\s*\)\s*\w")]
NOT_CALLS = {"Some"}


def count(code):
    """The number of calls in `code`, with each line after the first counting as one more."""
    calls = sum(1 for m in CALL.finditer(code) if m.group(1) not in NOT_CALLS)
    return calls + sum(len(p.findall(code)) for p in OTHER) + code.count("\n")


def level(calls):
    """The page's level for a call count, or for None when nothing compiled."""
    if calls is None:
        return "no fix found"
    return "as is" if calls == 0 else "one call" if calls == 1 else ">1 call"
