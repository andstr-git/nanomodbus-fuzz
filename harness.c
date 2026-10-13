/*  Гибридная обвязка для фаззинга nanoMODBUS
 *  afl-gcc-fast -o harness harness.c nanomodbus.c -I.  - AFL-режим (persistent, __AFL_LOOP)
 *  gcc --coverage -o harness_cov harness.c nanomodbus.c -I.  - coverage-режим (один прогон, вывод в stdin)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "nanomodbus.h"

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

/* Транспорт */

static const uint8_t *g_fuzz_data = NULL;
static size_t g_fuzz_len = 0;
static size_t g_fuzz_pos = 0;

static int32_t my_read(uint8_t *buf, uint16_t count, int32_t timeout, void *arg) {
    (void)arg;
    if (timeout == 0) return 0;
    if (g_fuzz_pos >= g_fuzz_len) return 0;

    size_t remaining = g_fuzz_len - g_fuzz_pos;
    size_t to_copy = (count < remaining) ? (size_t)count : remaining;
    memcpy(buf, g_fuzz_data + g_fuzz_pos, to_copy);
    g_fuzz_pos += to_copy;
    return (int32_t)to_copy;
}

static int32_t my_write(const uint8_t *buf, uint16_t count, int32_t timeout, void *arg) {
    (void)buf; (void)timeout; (void)arg;
    return (int32_t)count;
}

/* Коллбэки */

static nmbs_error cb_read_bits(uint16_t address, uint16_t quantity,
                               nmbs_bitfield bits_out, uint8_t unit_id, void *arg) {
    (void)address; (void)unit_id; (void)arg;
    for (uint16_t i = 0; i < quantity; i++)
        nmbs_bitfield_write(bits_out, i, (bool)(i & 1));
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_write_single_coil(uint16_t address, bool value,
                                       uint8_t unit_id, void *arg) {
    (void)address; (void)value; (void)unit_id; (void)arg;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_write_multiple_coils(uint16_t address, uint16_t quantity,
                                          const nmbs_bitfield bits,
                                          uint8_t unit_id, void *arg) {
    (void)address; (void)quantity; (void)bits; (void)unit_id; (void)arg;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_read_regs(uint16_t address, uint16_t quantity,
                               uint16_t *regs_out, uint8_t unit_id, void *arg) {
    (void)address; (void)unit_id; (void)arg;
    for (uint16_t i = 0; i < quantity; i++)
        regs_out[i] = (uint16_t)(0xAAAA + i);
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_write_single_register(uint16_t address, uint16_t value,
                                           uint8_t unit_id, void *arg) {
    (void)address; (void)value; (void)unit_id; (void)arg;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_write_multiple_registers(uint16_t address, uint16_t quantity,
                                              const uint16_t *regs,
                                              uint8_t unit_id, void *arg) {
    (void)address; (void)quantity; (void)regs; (void)unit_id; (void)arg;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_read_file_record(uint16_t file_number, uint16_t record_number,
                                      uint16_t *registers, uint16_t count,
                                      uint8_t unit_id, void *arg) {
    (void)file_number; (void)record_number; (void)unit_id; (void)arg;
    for (uint16_t i = 0; i < count; i++)
        registers[i] = (uint16_t)(0xBBBB + i);
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_write_file_record(uint16_t file_number, uint16_t record_number,
                                       const uint16_t *registers, uint16_t count,
                                       uint8_t unit_id, void *arg) {
    (void)file_number; (void)record_number; (void)registers;
    (void)count; (void)unit_id; (void)arg;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_read_device_identification(uint8_t object_id, char *buffer) {
    (void)object_id;
    strncpy(buffer, "nanoMODBUS", NMBS_DEVICE_IDENTIFICATION_STRING_LENGTH - 1);
    buffer[NMBS_DEVICE_IDENTIFICATION_STRING_LENGTH - 1] = 0;
    return NMBS_ERROR_NONE;
}

static nmbs_error cb_read_device_identification_map(nmbs_bitfield_256 map) {
    memset(map, 0, 32);
    nmbs_bitfield_write(map, 0, true);
    nmbs_bitfield_write(map, 1, true);
    nmbs_bitfield_write(map, 2, true);
    nmbs_bitfield_write(map, 3, true);
    nmbs_bitfield_write(map, 4, true);
    nmbs_bitfield_write(map, 5, true);
    nmbs_bitfield_write(map, 6, true);
    return NMBS_ERROR_NONE;
}


int main(void) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
#else
    static uint8_t stdin_buf[1024 * 1024];
#endif

    nmbs_t nmbs;
    nmbs_platform_conf platform_conf;
    nmbs_callbacks callbacks;

    nmbs_callbacks_create(&callbacks);
    callbacks.read_coils              = cb_read_bits;
    callbacks.read_discrete_inputs    = cb_read_bits;
    callbacks.read_holding_registers  = cb_read_regs;
    callbacks.read_input_registers    = cb_read_regs;
    callbacks.write_single_coil       = cb_write_single_coil;
    callbacks.write_multiple_coils    = cb_write_multiple_coils;
    callbacks.write_single_register   = cb_write_single_register;
    callbacks.write_multiple_registers = cb_write_multiple_registers;
    callbacks.read_file_record        = cb_read_file_record;
    callbacks.write_file_record       = cb_write_file_record;
    callbacks.read_device_identification = cb_read_device_identification;
    callbacks.read_device_identification_map = cb_read_device_identification_map;

    nmbs_platform_conf_create(&platform_conf);
    platform_conf.transport = NMBS_TRANSPORT_TCP;
    platform_conf.read      = my_read;
    platform_conf.write     = my_write;

    if (nmbs_server_create(&nmbs, 1, &platform_conf, &callbacks) != NMBS_ERROR_NONE)
        return 0;

    nmbs_set_read_timeout(&nmbs, 100);
    nmbs_set_byte_timeout(&nmbs, 100);

#ifdef __AFL_HAVE_MANUAL_CONTROL /* AFL-режим: persistent mode */
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        if (len == 0) continue;

        g_fuzz_data = buf;
        g_fuzz_len  = len;
        g_fuzz_pos  = 0;

        for (int iter = 0; iter < 100 && g_fuzz_pos < g_fuzz_len; iter++) {
            nmbs_error err = nmbs_server_poll(&nmbs);
            if (err != NMBS_ERROR_NONE && err != NMBS_ERROR_TIMEOUT) break;
        }
    }
#else     /* Coverage-режим: чтение из stdin один раз */
    {
        size_t len = fread(stdin_buf, 1, sizeof(stdin_buf), stdin);
        if (len > 0) {
            g_fuzz_data = stdin_buf;
            g_fuzz_len  = len;
            g_fuzz_pos  = 0;

            for (int iter = 0; iter < 100 && g_fuzz_pos < g_fuzz_len; iter++) {
                nmbs_error err = nmbs_server_poll(&nmbs);
                if (err != NMBS_ERROR_NONE && err != NMBS_ERROR_TIMEOUT) break;
            }
        }
    }
#endif

    return 0;
}
