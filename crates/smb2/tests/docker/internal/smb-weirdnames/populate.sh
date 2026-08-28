#!/bin/sh
# Files whose ON-DISK names are the private-use forms macOS smbfs writes.
#
# This is the interop contract, expressed as bytes: every name below was read
# off a QNAP TS-464 (Samba) over SSH after macOS created the file through a
# /Volumes SMB mount, on 2026-08-05. A test that lists this share and gets the
# plain characters back has proved the crate agrees with Finder about what this
# directory contains. Real Finder cannot run in Linux CI, so the bytes stand in
# for it -- which means these octal escapes are the assertion. Don't "tidy"
# them into the literal characters: Samba would then hold a different name and
# the test would pass while proving nothing.
#
#   \357\200\201 .. \357\200\237  U+F001..U+F01F  control 0x01..0x1F
#   \357\200\240  U+F020  "        \357\200\245  U+F025  ?
#   \357\200\241  U+F021  *        \357\200\246  U+F026  \
#   \357\200\242  U+F022  :        \357\200\247  U+F027  |
#   \357\200\243  U+F023  <        \357\200\250  U+F028  trailing space
#   \357\200\244  U+F024  >        \357\200\251  U+F029  trailing period
set -e

BASE="/shares/public"
mkdir -p "$BASE"

put() {
    printf 'content of %s\n' "$2" > "$BASE/$(printf "$1")"
}

# One file per character in the table, in an interior position.
put 'q\357\200\240uote'          'double quote'
put 'st\357\200\241ar'           'star'
put 'co\357\200\242lon'          'colon'
put 'l\357\200\243t'             'less than'
put 'g\357\200\244t'             'greater than'
put 'q\357\200\245mark'          'question mark'
put 'back\357\200\246slash'      'backslash'
put 'pi\357\200\247pe'           'pipe'
put 'ctrl\357\200\201one'        'control 0x01'
put 'ctrl\357\200\237last'       'control 0x1F'

# The trailing rule, and the fact that it takes the last character only.
put 'trailing-space\357\200\250'     'trailing space'
put 'trailing-period\357\200\251'    'trailing period'
put 'two-spaces \357\200\250'        'two trailing spaces, one mapped'
put 'two-periods.\357\200\251'       'two trailing periods, one mapped'
put 'period-then-space.\357\200\250' 'trailing period then space'

# Leading and interior positions that are NOT the trailing rule.
put '\357\200\245leading'        'leading question mark'
put ' leading-space'             'leading space is legal'
put '.leading-period'           'leading period is legal'
put 'interior period.and space' 'interior period and space are legal'

# Several substitutions in one name, including the real file that started this.
put 'all\357\200\240\357\200\241\357\200\242\357\200\243\357\200\244\357\200\245\357\200\246\357\200\247chars' 'every illegal character at once'
put '\357\200\240how_are_you_feeling\357\200\245\357\200\240_emojis.json' 'the name a QNAP share refused'

# A private-use code point outside the table has to survive untouched.
put 'outside-the-table-\357\200\252' 'U+F02A is not part of the scheme'

# The target for the exclusive-create collision test: a client whose encoding
# matches Finder's produces exactly this name and collides with it.
put 'collide\357\200\245me' 'collision target'

# Ordinary non-ASCII, to prove the mapping disturbs nothing it should not.
put 'plain-ascii.txt'            'ascii'
put '\346\227\245\346\234\254\350\252\236.txt'  'japanese'
put 'caf\303\251-nfc'            'e-acute precomposed'
put 'cafe\314\201-nfd'           'e plus combining acute, NOT normalized by us'
put '\360\237\223\201-emoji'     'emoji'

# Illegal characters in a DIRECTORY component, with a file inside, so a path
# has to be mapped per component rather than as one string.
mkdir -p "$BASE/$(printf 'su\357\200\245bdir')"
printf 'nested content\n' > "$BASE/$(printf 'su\357\200\245bdir')/$(printf 'in\357\200\241ner.txt')"
mkdir -p "$BASE/$(printf 'dir-trailing-space\357\200\250')"
printf 'deeper content\n' > "$BASE/$(printf 'dir-trailing-space\357\200\250')/$(printf 'le\357\200\246af')"

# A writable scratch directory, so a test that creates files can do it
# somewhere the listing assertions above don't see.
mkdir -p "$BASE/scratch"

chmod -R 777 "$BASE"
