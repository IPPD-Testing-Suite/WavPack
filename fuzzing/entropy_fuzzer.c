/*
 * entropy_fuzzer.c
 *
 * Targets Bug 3: signed integer overflow in wp_exp2s()
 * (src/entropy_utils.c:340)
 *
 * The bug fires when ID_ENTROPY_VARS metadata is parsed.  The local variable
 * `value` was changed from uint32_t to int32_t; when the log argument is
 * >= 0x2000, the left shift `value << ((log - 9) & 0x1f)` exceeds INT32_MAX,
 * which UBSan reports as signed-integer-overflow.
 *
 * read_entropy_vars() is called from process_metadata() during block
 * initialisation, so the overflow fires inside WavpackOpenFileInputEx64().
 * WavpackUnpackSamples() is also called to cover the per-block entropy path
 * for multi-block inputs.
 *
 * No tag operations are performed — they are unrelated to this bug.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "wavpack.h"

#define BUF_SAMPLES 1024

typedef struct {
    unsigned char ungetc_char, ungetc_flag;
    unsigned char *sptr, *dptr, *eptr;
    int64_t total_bytes_read;
} WavpackRawContext;

static int32_t raw_read_bytes(void *id, void *data, int32_t bcount)
{
    WavpackRawContext *rcxt = (WavpackRawContext *)id;
    unsigned char *outptr = (unsigned char *)data;

    while (bcount) {
        if (rcxt->ungetc_flag) {
            *outptr++ = rcxt->ungetc_char;
            rcxt->ungetc_flag = 0;
            bcount--;
        } else {
            size_t bytes_to_copy = rcxt->eptr - rcxt->dptr;
            if (!bytes_to_copy) break;
            if (bytes_to_copy > (size_t)bcount) bytes_to_copy = bcount;
            memcpy(outptr, rcxt->dptr, bytes_to_copy);
            rcxt->total_bytes_read += bytes_to_copy;
            rcxt->dptr += bytes_to_copy;
            outptr += bytes_to_copy;
            bcount -= bytes_to_copy;
        }
    }
    return (int32_t)(outptr - (unsigned char *)data);
}

static int32_t raw_write_bytes(void *id, void *data, int32_t bcount) { return data ? bcount : 0; }
static int64_t raw_get_pos(void *id) { WavpackRawContext *r = (WavpackRawContext *)id; return r->dptr - r->sptr; }
static int raw_set_pos_abs(void *id, int64_t pos) {
    WavpackRawContext *r = (WavpackRawContext *)id;
    if (r->sptr + pos < r->sptr || r->sptr + pos > r->eptr) return 1;
    r->dptr = r->sptr + pos; return 0;
}
static int raw_set_pos_rel(void *id, int64_t delta, int mode) {
    WavpackRawContext *r = (WavpackRawContext *)id;
    unsigned char *ref = NULL;
    if (mode == SEEK_SET) ref = r->sptr;
    else if (mode == SEEK_CUR) ref = r->dptr;
    else if (mode == SEEK_END) ref = r->eptr;
    if (ref + delta < r->sptr || ref + delta > r->eptr) return 1;
    r->dptr = ref + delta; return 0;
}
static int raw_push_back_byte(void *id, int c) { WavpackRawContext *r = (WavpackRawContext *)id; r->ungetc_char = c; r->ungetc_flag = 1; return c; }
static int64_t raw_get_length(void *id) { WavpackRawContext *r = (WavpackRawContext *)id; return r->eptr - r->sptr; }
static int raw_can_seek(void *id) { return 1; }
static int raw_close_stream(void *id) { return 0; }

static WavpackStreamReader64 raw_reader = {
    raw_read_bytes, raw_write_bytes, raw_get_pos, raw_set_pos_abs, raw_set_pos_rel,
    raw_push_back_byte, raw_get_length, raw_can_seek, NULL, raw_close_stream
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    WavpackRawContext raw_wv;
    WavpackContext *wpc;
    char error[80];
    int num_chans;

    memset(&raw_wv, 0, sizeof(raw_wv));
    raw_wv.dptr = raw_wv.sptr = (unsigned char *)data;
    raw_wv.eptr = raw_wv.dptr + size;

    /* UBSan overflow fires inside WavpackOpenFileInputEx64 when
       ID_ENTROPY_VARS metadata contains a log value >= 0x2000. */
    wpc = WavpackOpenFileInputEx64(&raw_reader, &raw_wv, NULL, error,
                                   OPEN_NO_CHECKSUM, 15);
    if (!wpc)
        return 0;

    /* Also decode samples: entropy vars are re-read per block during
       WavpackUnpackSamples, exercising the same overflow path for
       multi-block inputs. */
    num_chans = WavpackGetNumChannels(wpc);
    if (num_chans > 0 && num_chans <= 256) {
        int32_t *samples = (int32_t *)malloc(BUF_SAMPLES * num_chans * sizeof(int32_t));
        if (samples) {
            while (WavpackUnpackSamples(wpc, samples, BUF_SAMPLES) > 0)
                ;
            free(samples);
        }
    }

    WavpackCloseFile(wpc);
    return 0;
}
