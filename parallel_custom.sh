#!/bin/bash
# parallel_custom.sh — Параллельный фаззинг с кастомной мутацией (4 инстанса)

set -e

OUTPUT_DIR="/mnt/ramdisk/output_custom"
TIME_LIMIT=1800  # 30 минут

# core_pattern
echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null

# tmpfs
if [ ! -d /mnt/ramdisk ]; then
    sudo mkdir -p /mnt/ramdisk
    sudo mount -t tmpfs -o size=8G tmpfs /mnt/ramdisk
    sudo chown $USER:$USER /mnt/ramdisk
fi

# Очистка
rm -rf "$OUTPUT_DIR"

cd ~/nanomodbus-fuzz

# Проверка мутатора
if [ ! -f ./mbap_mutator.so ]; then
    echo "ERROR: mbap_mutator.so not found. Compile it first."
    exit 1
fi

echo "=== Параллельный фаззинг с кастомной мутацией ==="
echo "Output: $OUTPUT_DIR"
echo "Time: ${TIME_LIMIT}s"
echo "Mutator: ./mbap_mutator.so"
echo ""

# Функция запуска
run_instance() {
    local role=$1
    local name=$2
    AFL_CUSTOM_MUTATOR_LIBRARY=./mbap_mutator.so \
        afl-fuzz -i seeds -o "$OUTPUT_DIR" -$role "$name" \
        -- ./harness > /tmp/afl_custom_${name}.log 2>&1 &
    echo "  Started $name (PID $!)"
}

# Запуск 4 инстансов
run_instance M main
sleep 5  # дать main создать output
run_instance S sec1
run_instance S sec2
run_instance S sec3

echo ""
echo "All 4 instances started. Waiting ${TIME_LIMIT}s..."
sleep $TIME_LIMIT

# Остановка
echo ""
echo "=== Stopping ==="
pkill -f "afl-fuzz.*output_custom" || true
sleep 3

# Статистика
echo ""
echo "=== CUSTOM (4 instances) ==="
for name in main sec1 sec2 sec3; do
    if [ -f "$OUTPUT_DIR/$name/fuzzer_stats" ]; then
        echo "--- $name ---"
        grep -E "execs_done|corpus_count|saved_crashes|bitmap_cvg|stability" \
            "$OUTPUT_DIR/$name/fuzzer_stats"
        echo ""
    fi
done

echo "Done. Results in $OUTPUT_DIR"