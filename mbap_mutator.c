/* Кастомная мутация для Modbus TCP

 * 1. Пересчитывает MBAP Length после мутации (чтобы сервер не отбрасывал пакет)
 * 2. Для FC 0x14 (Read File Record) - дублирует подзапросы,
 *    что увеличивает шанс триггера stack-buffer-overflow в handle_read_file_record
 * 3. Корректирует ByteCount для FC 0x14
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_INPUT 4096

static uint8_t mut_buf[MAX_INPUT];
static unsigned int rng_state = 0x12345678;

static unsigned int lcg_rand(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void)afl;
    rng_state = seed;
    return NULL;
}

 /* функция мутации: AFL++ вызывает её вместо/вместе со стандартными мутациями. */
size_t afl_custom_fuzz(void *data,
                       uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    (void)data; (void)add_buf; (void)add_buf_size;

    if (buf_size < 8) return 0;  /* слишком короткий для MBAP */
    if (buf_size > MAX_INPUT) buf_size = MAX_INPUT;

    memcpy(mut_buf, buf, buf_size);

    /* проверка, что это Modbus TCP */
    if (mut_buf[2] != 0 || mut_buf[3] != 0) {
        *out_buf = mut_buf;
        return buf_size;
    }

    uint8_t fc = mut_buf[7];

    /* спец. обработка FC 0x14 (Read File Record) - дублирование последнего поздапроса */
    if (fc == 0x14 && buf_size >= 9) {
        uint8_t byte_count = mut_buf[8];
        size_t num_subreqs = byte_count / 7;

        if (num_subreqs > 0 && num_subreqs < 35 && buf_size + 7 <= max_size) {
            size_t last_subreq_offset = 9 + (num_subreqs - 1) * 7;
            if (last_subreq_offset + 7 <= buf_size) {
                memcpy(mut_buf + buf_size, mut_buf + last_subreq_offset, 7);
                buf_size += 7;
                num_subreqs++;
                mut_buf[8] = (uint8_t)(num_subreqs * 7);
            }
        }
    }

    /* пересчёт MBAP Length = количество байт после Length = 1 (Unit) + PDU */
    size_t pdu_size = buf_size - 7;
    uint16_t mbap_length = (uint16_t)pdu_size;
    mut_buf[4] = (mbap_length >> 8) & 0xFF;
    mut_buf[5] = mbap_length & 0xFF;

    *out_buf = mut_buf;
    return buf_size;
}

void afl_custom_deinit(void *data) {
    (void)data;
}