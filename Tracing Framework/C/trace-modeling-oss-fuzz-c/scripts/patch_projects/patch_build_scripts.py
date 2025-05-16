# for all projects:     python scripts/patch_projects/audit_build_scripts.py | patch -p0
# for specific project: python scripts/patch_projects/audit_build_scripts.py | filterdiff -i projects/apache-httpd/build.sh | patch -p0
# save patch file:      python scripts/patch_projects/patch_build_scripts.py > data/patch_build_scripts.patch &> logs/build_with_debugger/patch_build_scripts.log

import re
import os
from loguru import logger
import difflib

def add_cflags_line(text):
    lines = text.splitlines(keepends=True)
    first_idx_without_comment = next(i for i,l in enumerate(lines) if not l.lstrip().startswith("#"))
    lines.insert(first_idx_without_comment, '''function filter() { echo $1 | sed 's/-O[0-9]//g'; }
export CFLAGS="$(filter $CFLAGS) -g -O0"
export CXXFLAGS="$(filter $CXXFLAGS) -g -O0"
''')
    return "".join(lines)

def audit(fpath):
    if not os.path.exists(fpath):
        logger.warning("{} not found", fpath)
        return
    CONFIGURE_REGEX = re.compile(r"\b(./)?(?P<command>configure)\b")
    CMAKE_REGEX = re.compile(r"\b(?P<command>cmake)\b")
    MESON_REGEX = re.compile(r"\b(?P<command>meson)\b")
    MAKE_REGEX = re.compile(r"\b(?P<command>make)\b")
    OSSFUZZ_BUILD_SCRIPT_REGEX = re.compile(r"(?P<command>(python|bash)\s+oss[-_]?fuzz|fuzz.*/build|build-fuzzers)\.(sh|py)")

    # CFLAGS_SUB = r'CFLAGS="$CFLAGS -g -O0" CXXFLAGS="$CXXFLAGS -g -O0" \g<command>'

    with open(fpath) as f:
        text = f.read()
    orig_text = text
    logger.debug("{} lines", len(text))
    # text = add_cflags_line(text)  # DEPRECATED: these options are already added to the environment in the base-builder Dockerfile.
    if CONFIGURE_REGEX.search(text):
        text = CONFIGURE_REGEX.sub(r"\g<command> --enable-debug", text)
    elif CMAKE_REGEX.search(text):
        text = CMAKE_REGEX.sub(r"\g<command> -DCMAKE_BUILD_TYPE=Debug", text)
    # elif MAKE_REGEX.search(text):
    #     new_text = add_cflags_line(text)
    # elif MESON_REGEX.search(text):
    #     new_text = add_cflags_line(text)
    # elif OSSFUZZ_BUILD_SCRIPT_REGEX.search(text):
    #     new_text = add_cflags_line(text)
    else:
        logger.warning("not handled: {}", fpath)
    if orig_text != text:
        # logger.debug("diff {}:\n{}", fpath, "".join(difflib.unified_diff(orig_text.splitlines(keepends=True), new_text.splitlines(keepends=True), fromfile=fpath, tofile=fpath)))
        diff = "".join(difflib.unified_diff(orig_text.splitlines(keepends=True), text.splitlines(keepends=True), fromfile=fpath, tofile=fpath))
        print(diff)

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("input_file", nargs='?')
args = parser.parse_args()

if args.input_file:
    audit(args.input_file)
else:
    with open("data/projects_c.txt") as f:
        for line in f:
            build_file = os.path.join("projects", line.strip(), "build.sh")
            audit(build_file)
