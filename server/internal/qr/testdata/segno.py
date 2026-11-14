# SPDX-License-Identifier: AGPL-3.0-or-later
"""Writes segno.json: QR codes that segno drew, which the Go encoder must match module for module.

segno is an independent, pure-Python QR code encoder. Run it in a virtual environment of its own:

    python3 -m venv /tmp/segno
    /tmp/segno/bin/pip install --require-hashes -r requirements.txt
    /tmp/segno/bin/python -I segno.py > segno.json

- "all": every version from 1 to 40 at every level, each filled to capacity in byte mode with
  data[i] = (31 i + 7 version + level) mod 256 and the fixed mask (4 version + level) mod 8, as
  the SHA-256 of its rows ("0" light, "1" dark, one row per line).
- "auto": codes filled to capacity with data[i] = (17 i + 3) mod 256 and the mask segno chose by
  the standard's penalty rules, as the SHA-256 of their rows, and the rows themselves for the
  smallest. "scores" are segno's four penalty scores (N1, N2, N3, N4) for each mask, judged as
  its encoder judges them, from its internal functions.

Every code is filled to capacity because segno pads differently below it. Where the terminator
already ends on a byte boundary, which in byte mode it does whenever all four of its bits fit,
segno adds a further byte of zero bits before the pad codewords; ISO/IEC 18004:2015, 7.4.10, adds
padding bits only to reach a boundary. Both decode alike, but the codewords differ.
"""
import hashlib
import json

import segno
from segno import consts, encoder

LEVELS = "LMQH"


def rows(qr):
    return ["".join("1" if m else "0" for m in row) for row in qr.matrix]


def make(data, level, version=None, mask=None):
    return segno.make(data, mode="byte", error=LEVELS[level].lower(), version=version, mask=mask,
                      boost_error=False, micro=False)


def data_for(version, level, n):
    return bytes((31 * i + 7 * version + level) % 256 for i in range(n))


def capacity(version, level):
    lo, hi = 1, 3000
    while lo < hi:  # the longest data that fits
        mid = (lo + hi + 1) // 2
        try:
            make(data_for(version, level, mid), level, version, mask=0)
            lo = mid
        except segno.DataOverflowError:
            hi = mid - 1
    return lo


everything = []
for version in range(1, 41):
    for level in range(4):
        n, mask = capacity(version, level), (4 * version + level) % 8
        qr = make(data_for(version, level, n), level, version, mask)
        assert qr.version == version and qr.mask == mask and qr.error == LEVELS[level]
        digest = hashlib.sha256("\n".join(rows(qr)).encode()).hexdigest()
        everything.append(dict(version=version, level=LEVELS[level], length=n, mask=mask, sha256=digest))

def scores(data, version, level):
    """segno's (N1, N2, N3, N4) for each mask, on the matrix its encoder judges: the codewords
    placed, the format and version information still light. Follows encoder._encode."""
    error = getattr(consts, "ERROR_LEVEL_" + LEVELS[level])
    buff = encoder.Buffer()
    for segment in encoder.prepare_data(data, consts.MODE_BYTE, None):
        encoder.write_segment(buff, segment, None, encoder.version_range(version), False)
    capacity = consts.SYMBOL_CAPACITY[version][error]
    encoder.write_terminator(buff, capacity, None, len(buff))
    encoder.write_padding_bits(buff, version, len(buff))
    encoder.write_pad_codewords(buff, version, capacity, len(buff))
    buff = encoder.make_final_message(version, error, buff)
    size = encoder.calc_matrix_size(version)
    matrix = encoder.make_matrix(size, size)
    encoder.add_finder_patterns(matrix, size, size)
    encoder.add_alignment_patterns(matrix, size, size)
    encoder.add_codewords(matrix, buff, version)
    function_matrix = encoder.make_matrix(size, size)
    encoder.add_finder_patterns(function_matrix, size, size)
    encoder.add_alignment_patterns(function_matrix, size, size)
    function_matrix[-8][8] = 0x1
    out = []
    for pattern in encoder.get_data_mask_functions(False):
        m = [bytearray(row) for row in matrix]
        encoder.apply_mask(m, pattern, size, size, lambda i, j: function_matrix[i][j] > 0x1)
        out.append(list(encoder.mask_scores(m, size, size)))
    return out


auto = []
for version, level in [(1, 1), (2, 0), (3, 3), (5, 2), (7, 3), (8, 1), (10, 0), (13, 1), (20, 2), (27, 3), (33, 0),
                       (40, 1)]:
    n = capacity(version, level)
    data = bytes((17 * i + 3) % 256 for i in range(n))
    qr = make(data, level)
    assert qr.version == version and qr.error == LEVELS[level]
    s = scores(data, version, level)
    assert min(range(8), key=lambda m: sum(s[m])) == qr.mask
    case = dict(version=version, level=LEVELS[level], length=n, mask=qr.mask, scores=s,
                sha256=hashlib.sha256("\n".join(rows(qr)).encode()).hexdigest())
    if version <= 2:
        case["rows"] = rows(qr)
    auto.append(case)

print(json.dumps(dict(generator="segno " + segno.__version__, all=everything, auto=auto), indent=1))
