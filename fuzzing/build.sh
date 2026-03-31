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

# build project
# Bug 3 requires UBSan signed-integer-overflow, so do NOT suppress it here.
./autogen.sh --disable-apps --disable-shared --enable-static
./configure --disable-apps --disable-shared --enable-static
make

# build fuzzers
for HARNESS in channel_identities binary_tag entropy id3_tag append_tag; do
    $CC $CFLAGS -std=c11 -I$SRC/wavpack/include -include stdio.h \
        $SRC/wavpack/fuzzing/${HARNESS}_fuzzer.c -o $OUT/${HARNESS}_fuzzer \
        $LIB_FUZZING_ENGINE $SRC/wavpack/src/.libs/libwavpack.a
done

# add seed corpora
cp $SRC/wavpack/fuzzing/*_seed_corpus.zip $OUT/

# add dictionary and options
cp $SRC/wavpack/fuzzing/*.dict $SRC/wavpack/fuzzing/*.options $OUT/
