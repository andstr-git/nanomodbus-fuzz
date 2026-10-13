# Отчёт фаззинга библиотеки nanoMODBUS
## О проекте

**[nanoMODBUS](https://github.com/debevv/nanoMODBUS)** – компактная C99-библиотека, реализующая протокол **Modbus RTU/TCP** для встраиваемых систем.

**Modbus TCP** – stateful-протокол прикладного уровня, используемый в промышленной автоматизации (SCADA, PLC, датчики). Обмен построен на модели «клиент (master) – сервер (slave)»: клиент отправляет запросы по функциональным кодам (FC), сервер обрабатывает их и возвращает ответы. Соединение поддерживает состояние между запросами.

## Сценарии работы приложения

Для тестирования библиотеки была написана минимальная обвязка `harness.c`, реализующая экземпляр Modbus-сервера, который эмулирует поведение реального slave-устройства в промышленной сети. Сетевой обмен эмулируется чтением данные из буфера AFL вместо сокета:
Она поддерживает работу в двух режимах:
- **AFL-режим** (`afl-gcc-fast`) – многократный цикл через `__AFL_LOOP`.
- **Coverage-режим** (`gcc --coverage`) – один прогон, чтение из stdin.


### Сценарий обработки одного теста

Обвязка обрабатывает **несколько Modbus-запросов за один вход** – это воспроизводит реальное поведение сервера в промышленной сети, где master отправляет последовательность команд:

```c
for (int iter = 0; iter < 100 && g_fuzz_pos < g_fuzz_len; iter++) {
    nmbs_error err = nmbs_server_poll(&nmbs);
    if (err != NMBS_ERROR_NONE && err != NMBS_ERROR_TIMEOUT) break;
}
```

Цикл вызывает `nmbs_server_poll` до тех пор, пока в буфере есть данные или пока сервер не вернёт ошибку (кроме таймаута). Это позволяет фаззеру исследовать **stateful-поведение**: последовательности запросов, накопление состояния сервера.

### Покрываемые функциональные коды

Seed-корпус из 15 файлов охватывает все 12 функциональных кодов Modbus TCP:

| FC | Файл | Описание | Ветка обработки |
| :--- | :--- | :--- | :--- |
| 0x01 | `fc01_read_coils` | Read Coils | `handle_read_discrete` |
| 0x02 | `fc02_read_discrete` | Read Discrete Inputs | `handle_read_discrete` |
| 0x03 | `fc03_read_holding` | Read Holding Registers | `handle_read_registers` |
| 0x04 | `fc04_read_input` | Read Input Registers | `handle_read_registers` |
| 0x05 | `fc05_write_coil` | Write Single Coil | `handle_write_single_coil` |
| 0x06 | `fc06_write_reg` | Write Single Register | `handle_write_single_register` |
| 0x0F | `fc0f_write_coils` | Write Multiple Coils | `handle_write_multiple_coils` |
| 0x10 | `fc10_write_regs` | Write Multiple Registers | `handle_write_multiple_registers` |
| 0x14 | `fc14_read_file` | Read File Record | `handle_read_file_record` |
| 0x15 | `fc15_write_file` | Write File Record | `handle_write_file_record` |
| 0x17 | `fc17_readwrite` | Read/Write Multiple Registers | `handle_read_write_registers` |
| 0x2B | `fc2b_read_devid` | Read Device Identification | `handle_read_device_identification` |

Seed `fc14_read_file` содержит 5 подзапросов по `record_length=124` – это уже триггерит уязвимость в `handle_read_file_record` (описанную ниже) без мутаций.

### Кастомная мутация

Файл `mbap_mutator.c` – библиотека `mbap_mutator.so`, подключаемая к AFL++ через `AFL_CUSTOM_MUTATOR_LIBRARY`. Она пытается воспроизвести уже [выявленную сообществом уязвимость в серверной части](https://github.com/debevv/nanoMODBUS/issues/128) путём дублирования подзапросы FC 0x14 для увеличения шанса триггера переполнения в `handle_read_file_record`

## Команды сборки и запуска

### Сборка

```bash
# AFL-версия (для фаззинга)
AFL_QUIET=1 afl-gcc-fast -o harness harness.c nanomodbus.c -I.

# Coverage-версия (для LCOV)
gcc --coverage -o harness_cov harness.c nanomodbus.c -I.
```

### Запуск фаззинга

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern

# Прогон 1: дефолтные мутации
afl-fuzz -i seeds -o output-part1 -- ./harness

# Прогон 2: кастомная мутация
AFL_CUSTOM_MUTATOR_LIBRARY=./mbap_mutator.so \
    afl-fuzz -i seeds -o output-part2 -- ./harness
```
## 5. Результаты
#### Первый прогон:
<img height="480" alt="изображение" src="https://github.com/user-attachments/assets/54c54b30-b523-4f34-a16f-ac01b06b8618" />

#### Прогон с мутациями:
<img height="480" alt="изображение" src="https://github.com/user-attachments/assets/0df0d468-7c5e-44a6-a0ba-8755e17ba215" />



### Сравнение прогонов

| Метрика | part1 | part2 |
| :--- | :--- | :--- |
| Длительность | 33 мин | 30.5 мин |
| Executions | 307.6M | 320.1M |
| Exec speed | ~155k/сек | ~174k/сек |
| Corpus count | 639 | 443 |
| Bitmap coverage | **1.10%** | 0.64% |
| Saved crashes | **102** | 71 |
| Stability | 99.86% | 99.76% |

Кастомная мутация не дала преимущества для данной цели. Причина: seed `fc14_read_file` уже триггерит уязвимость без мутаций, а специализированный мутатор тратит disproportionate время на FC 0x14, снижая покрытие других FC.

### Классификация крашей

Из 102 крашей в `output-part1`:
- **SIGSEGV** (sig:11): 44
- **SIGABRT** (sig:06): 58

### LCOV-отчёт
Итоговое покрытие корпуса `output-part1/default/queue/` (639 файлов):
<img height="420" alt="изображение" src="https://github.com/user-attachments/assets/abed8845-4f8d-4b9d-9ec0-390d7240472a" />

Неполное покрытие объясняется тем, что часть корпуса крашит сервер до выполнения остального кода. Также не покрыты клиентские функции, поскольку обвязка фаззит только серверную часть.

## 6. Разбор найденных крашей

ASan-анализ выявил **6 мест падения** в `nanomodbus.c`. Пять из них – **каскадные** от одного первичного бага.

| # | Функция | Строка | Тип | Роль |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `handle_read_file_record` | 1401 | stack-buffer-overflow | **Первичный** |
| 2 | `handle_read_registers` | 995 | SEGV | Каскадный |
| 3 | `handle_write_single_register` | 1135 | SEGV | Каскадный |
| 4 | `handle_write_single_coil` | 1084 | SEGV | Каскадный |
| 5 | `flush` | 188 | SEGV | Каскадный |
| 6 | `handle_read_discrete` | 930 | SEGV | Каскадный |

### Первичный баг: stack-buffer-overflow в `handle_read_file_record`

**ASan**:
```
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 2
  #0 cb_read_file_record harness.c:108
  #1 handle_read_file_record nanomodbus.c:1401
  #2 handle_req_fc nanomodbus.c:1864
  #3 nmbs_server_poll nanomodbus.c:1943
Address is located in stack of thread T0 at offset 1273 in frame
  [816, 1272) 'nmbs' <== Memory access at offset 1273 overflows this variable
```

**Причина**:

В `struct nmbs_t` (`nanomodbus.h`) буфер `msg.buf` имеет размер **260 байт**. При обработке FC 0x14 функция `handle_read_file_record` для каждого подзапроса вызывает `get_n(nmbs, subreq_data_size)`, где `subreq_data_size = record_length * 2`. Функция `get_n` **не проверяет границы** и сдвигает `buf_idx` на `subreq_data_size`.

При запросе с 5 подзапросами по `record_length = 124` (валидное значение по спецификации, <= 124) суммарный размер составляет **1240 байт** – превышение буфера в 4.7 раза. Колбэк `cb_read_file_record` пишет по указателю за пределами `msg.buf`, повреждая структуру `nmbs` (включая указатели на колбэки), что вызывает каскадные SEGV в других функциях.
Этот баг позволяет вредоносному клиенту Modbus TCP крашнуть сервер. По спецификации сервер обязан валидировать входные данные, а не падать.
Этот баг, хоть и возникает в том же коде FC 0x14, представляет собой другой, **<u>новый баг</u>**, обнаруженный в результате моего фаззинга (переполнение `uint8_t` аккумулятора `response_data_size`)

### Предлагаемый фикс

Минимальная проверка границ перед вызовом колбэка в `handle_read_file_record`:

```diff
--- a/nanomodbus.c
+++ b/nanomodbus.c
@@ -1385,6 +1385,12 @@ static nmbs_error handle_read_file_record(nmbs_t* nmbs) {
         if (subreq[i].record_length > 124)
             return send_exception_msg(nmbs, NMBS_EXCEPTION_ILLEGAL_DATA_ADDRESS);
 
+        /* Проверка, не выходим ли за границы msg.buf (260 байт, согласно nanomodbus.h) */
+        if (nmbs->msg.buf_idx + (subreq[i].record_length * 2) > sizeof(nmbs->msg.buf)) {
+            return send_exception_msg(nmbs, NMBS_EXCEPTION_ILLEGAL_DATA_VALUE);
+        }
+
         NMBS_DEBUG_PRINT(...);
     }
```
