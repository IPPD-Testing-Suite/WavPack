#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
    int flags = OPEN_TAGS | OPEN_EDIT_TAGS | OPEN_WRAPPER | OPEN_DSD_AS_PCM | OPEN_NO_CHECKSUM | OPEN_NORMALIZE |
        (4 << OPEN_THREADS_SHFT);
    WavpackRawContext raw_wv;
    WavpackContext *wpc;
    char error[80];
    int num_chans, mode;
    int64_t total_samples;
    int retval = 0;

    memset(&raw_wv, 0, sizeof(WavpackRawContext));
    raw_wv.dptr = raw_wv.sptr = (unsigned char *)data;
    raw_wv.eptr = raw_wv.dptr + size;
    wpc = WavpackOpenFileInputEx64(&raw_reader, &raw_wv, NULL, error, flags, 15);

    if (!wpc) { retval = 1; goto exit_fn; }

    num_chans = WavpackGetNumChannels(wpc);
    total_samples = WavpackGetNumSamples64(wpc);
    mode = WavpackGetMode(wpc);

    if (mode & MODE_VALID_TAG) {
        int num_binary_items = WavpackGetNumBinaryTagItems(wpc);
        int num_items = WavpackGetNumTagItems(wpc), i;

        for (i = 0; i < num_items; ++i) {
            int item_len, value_len;
            char *item, *value;

            item_len = WavpackGetTagItemIndexed(wpc, i, NULL, 0);
            item = (char *)malloc(item_len + 1);
            WavpackGetTagItemIndexed(wpc, i, item, item_len + 1);
            value_len = WavpackGetTagItem(wpc, item, NULL, 0);
            value = (char *)malloc(value_len + 1);
            WavpackGetTagItem(wpc, item, value, value_len + 1);
            free(value);
            free(item);
        }

        for (i = 0; i < num_binary_items; ++i) {
            int item_len, value_len;
            char *item, *value;

            item_len = WavpackGetBinaryTagItemIndexed(wpc, i, NULL, 0);
            item = (char *)malloc(item_len + 1);
            WavpackGetBinaryTagItemIndexed(wpc, i, item, item_len + 1);
            value_len = WavpackGetBinaryTagItem(wpc, item, NULL, 0);
            value = (char *)malloc(value_len);
            WavpackGetBinaryTagItem(wpc, item, value, value_len);
            free(value);
            free(item);
        }

        WavpackAppendTagItem(wpc, "Artist", "The Googlers", strlen("The Googlers"));
        WavpackAppendTagItem(wpc, "Title", "Fuzz Me All Night Long", strlen("Fuzz Me All Night Long"));
        WavpackAppendTagItem(wpc, "Album", "Meet The Googlers", strlen("Meet The Googlers"));
        WavpackAppendBinaryTagItem(wpc, "Cover Art (Front)", (const char *)data, size < 4096 ? size : 4096);
    }

    if (num_chans && num_chans <= 256) {
        int32_t *decoded_samples = (int32_t *)malloc(BUF_SAMPLES * num_chans * sizeof(int32_t));
        int unpack_result;

        do {
            unpack_result = WavpackUnpackSamples(wpc, decoded_samples, BUF_SAMPLES);
        } while (unpack_result);

        free(decoded_samples);
    }

    if (WavpackSeekSample64(wpc, total_samples / 3 + 1000))
        WavpackWriteTag(wpc);

    WavpackCloseFile(wpc);

exit_fn:
    return retval;
}
