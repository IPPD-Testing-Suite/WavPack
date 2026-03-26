/*
 * id3_tag_fuzzer.c
 *
 * Targets Bug 4: stack buffer overflow in get_id3_tag_item()
 * (src/tag_utils.c:288)
 *
 * The bug fires when WavpackGetTagItem() is called on a file that has an
 * ID3v1 tag.  Inside get_id3_tag_item(), `tagcpy()` is called with
 * sizeof(field)=30 as the source limit, but the destination buffer `lvalue`
 * was shrunk from 64 bytes to 4 bytes.  Any title (or other field) with
 * >= 4 non-space, non-null characters overflows the stack buffer.
 *
 * The overflow occurs even on the size-query call (NULL destination) because
 * tagcpy fills `lvalue` before the NULL check.
 *
 * Only text (non-binary) tag items are exercised here.  Binary items and
 * sample decoding cannot reach get_id3_tag_item().
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "wavpack.h"

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
    int mode;

    memset(&raw_wv, 0, sizeof(raw_wv));
    raw_wv.dptr = raw_wv.sptr = (unsigned char *)data;
    raw_wv.eptr = raw_wv.dptr + size;

    wpc = WavpackOpenFileInputEx64(&raw_reader, &raw_wv, NULL, error,
                                   OPEN_TAGS | OPEN_NO_CHECKSUM, 15);
    if (!wpc)
        return 0;

    mode = WavpackGetMode(wpc);

    if (mode & MODE_VALID_TAG) {
        int num_items = WavpackGetNumTagItems(wpc);
        int i;

        for (i = 0; i < num_items; ++i) {
            int item_len, value_len;
            char *item, *value;

            /* Get the item name via the indexed call (uses get_id3_tag_item_indexed,
               which has an adequate buffer and is not vulnerable). */
            item_len = WavpackGetTagItemIndexed(wpc, i, NULL, 0);
            item = (char *)malloc(item_len + 1);
            if (!item) continue;
            WavpackGetTagItemIndexed(wpc, i, item, item_len + 1);

            /* WavpackGetTagItem -> get_id3_tag_item -> tagcpy into lvalue[4].
               The stack overflow fires here for any field value >= 4 chars. */
            value_len = WavpackGetTagItem(wpc, item, NULL, 0);
            value = (char *)malloc(value_len + 1);
            if (value) {
                WavpackGetTagItem(wpc, item, value, value_len + 1);
                free(value);
            }
            free(item);
        }
    }

    WavpackCloseFile(wpc);
    return 0;
}
