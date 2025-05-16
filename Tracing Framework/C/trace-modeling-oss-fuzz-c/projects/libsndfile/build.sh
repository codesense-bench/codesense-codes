#!/bin/bash -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

if [ "$BUILD_LLM_HARNESSES" = true ]
then
cp /llm-generated/harness_*.cc ossfuzz/
sed -i -e '467s/$/ \\/' -e "468i $(ls -1 ossfuzz/harness_*.cc | sed 's/\.cc$//' | xargs echo)" Makefile.am
# TODO: WIP. Finish implementing
for f in $(ls -1 ossfuzz/harness_*.cc | sed -e 's/\.cc$//' -e 's@^ossfuzz/@@')
do
sed -i "483i ossfuzz_${f}_SOURCES = ossfuzz/sndfile_alt_fuzzer.cc\\
ossfuzz_${f}_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)\\
ossfuzz_${f}_LDFLAGS = $(AM_LDFLAGS) -static\\
ossfuzz_${f}_LDADD = src/libsndfile.la $(FUZZ_LDADD)\\
" Makefile.am
done
fi

# Run the OSS-Fuzz script in the project.
apt-get update
./ossfuzz/ossfuzz.sh

if [ "$BUILD_LLM_HARNESSES" = true ]
then
cp -v ossfuzz/harness_* $OUT/
fi

# To make CIFuzz fast, see here for details: https://github.com/libsndfile/libsndfile/pull/796
for fuzzer in sndfile_alt_fuzzer sndfile_fuzzer; do
  echo "[libfuzzer]" > ${OUT}/${fuzzer}.options
  echo "close_fd_mask = 3" >> ${OUT}/${fuzzer}.options
done
