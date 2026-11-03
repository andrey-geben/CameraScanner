# CameraScanner

> Утилита активного обнаружения IP-камер в локальной сети с современным GUI в стиле Windows 11.

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.3.0-blue)]()

**CameraScanner** — настольное приложение для быстрого поиска IP-камер и сетевых видеорегистраторов в локальной сети. Поддерживает семь независимых протоколов обнаружения — от быстрых broadcast/multicast до активного перебора адресов и портов, что позволяет находить камеры, у которых отключены штатные службы обнаружения.

---

## ✨ Возможности

### Broadcast / Multicast — без указания подсети, в пределах L2-сегмента

| Протокол | Механизм | Что находит |
|---|---|---|
| **ONVIF WS-Discovery** | SOAP `Probe` на multicast `239.255.255.250:3702` + broadcast-фоллбэк | Все ONVIF-совместимые камеры и NVR |
| **SADP (Hikvision)** | UDP multicast `239.255.255.250/.230:37020` + broadcast | Hikvision: MAC, серийник, модель, прошивка, статус активации |
| **Dahua / Amcrest** | UDP broadcast `:37810`, JSON | Dahua/Amcrest, включая устройства с отключённым ONVIF |

### Active scanning — перебор адресов, работает в пределах подсети

| Протокол | Механизм | Что находит |
|---|---|---|
| **SNMP v1 / v2c / v3** | GET-запросы на UDP/161 | Устройства с открытым SNMP: MIB-II + вендорские OID Hikvision |
| **ARP (ping sweep)** | Параллельный ICMP + системная ARP-таблица | «Молчащие» устройства, которые не отвечают на SADP/ONVIF/SNMP |
| **TCP port scan** | Проверка портов `80, 443, 554, 8000, 8080, 8443, 37777, 34567` | Открытые сервисы, характерные для камер и NVR; эвристика вендора |
| **ISAPI probe (Hikvision)** | HTTP GET `/ISAPI/System/deviceInfo` | Модель, серийник и прошивка Hikvision; при 401 — данные из `WWW-Authenticate` |

### Дополнительно

- 🖥️ **Современный интерфейс** на Sun Valley (тема Windows 11) с переключением светлая/тёмная.
- 🔒 **Запрос прав администратора по требованию** — только при включении SADP. Все параметры формы сохраняются при UAC-перезапуске.
- ⚠️ **Модальное предупреждение перед сканированием** — напоминает, что сетевой скан виден службам ИБ и должен быть согласован.
- 🛑 **Кнопка «Стоп»** — прерывает сканирование с сохранением уже найденных результатов.
- 📊 **Экспорт в CSV** — все поля всех протоколов в одной таблице.
- 📚 **Встроенная справка** — меню «Справка → Способы сканирования» с описанием каждого протокола.
- 🎨 **Кастомная иконка** и диалог «О программе» с копирайтом.
- 📦 **Сборка в один `.exe`** через PyInstaller.

---

## 📋 Требования

- **ОС:** Windows 10 (1809+) или Windows 11 (x64)
- **Python:** 3.12+
- **Сеть:** доступ в локальный сегмент, где находятся камеры
- **Права:** обычные — для всех протоколов, кроме SADP; для SADP — администратор
- **Среда:** Microsoft Visual C++ Redistributable 2015–2022 (x64) — обычно уже установлен, но на «чистых» системах может потребоваться

> ⚠️ **Multicast/broadcast не проходят через маршрутизатор.** ONVIF/SADP/Dahua находят устройства только в том же L2-сегменте (VLAN). Для поиска за роутером используйте SNMP-перебор по подсети (при условии, что SNMP открыт).

---

## 🚀 Установка

### 1. Клонирование и виртуальное окружение

```bash
git clone https://github.com/andrey-geben/CameraScanner.git
cd CameraScanner

python -m venv .venv
.venv\Scripts\activate
```

### 2. Зависимости

```bash
pip install -r requirements.txt
```

### ⚠️ Если `netifaces` не устанавливается

Пакет `wsdiscovery` зависит от `netifaces`, у которого **нет официального wheel для Python 3.12 на Windows**, и `pip` пытается собрать его из исходников (требуется Microsoft C++ Build Tools).

**Решение — установить готовый wheel от Odoo:**

```bash
pip install https://nightly.odoo.com/wheels/netifaces-0.11.0-cp312-cp312-win_amd64.whl
pip install -r requirements.txt
```

**Альтернатива** — установить [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (несколько ГБ, но универсально).

---

## 🎮 Запуск

### Обычный запуск

```bash
python main.py
```

### С правами администратора (для SADP)

Либо поставьте галочку **«SADP (Hikvision)»** в интерфейсе — приложение само вызовет UAC и перезапустится с сохранением всех настроек. Либо запустите сразу:

```bash
python main.py --elevated
```

### Доступные аргументы CLI

| Аргумент | Назначение |
|---|---|
| `--elevated` | Маркер, что процесс уже с правами администратора |
| `--subnet 192.168.1.0/24` | Предзаполнить подсеть |
| `--community public` | SNMP community |
| `--snmp-version v2c` | Версия SNMP: `v1`, `v2c`, `v3` |
| `--auto 0\|1` | Режим автообнаружения |
| `--snmp 0\|1` | SNMP |
| `--onvif 0\|1` | ONVIF |
| `--dahua 0\|1` | Dahua |
| `--arp 0\|1` | ARP ping sweep |
| `--portscan 0\|1` | TCP port scan |
| `--isapi 0\|1` | ISAPI probe |

Все аргументы используются внутренне при UAC-перезапуске и могут быть переданы вручную.

---

## 🖱️ Как пользоваться

### Режим «Подсеть»

1. Введите CIDR-нотацию подсети (например, `192.168.1.0/24`).
2. Укажите SNMP community (по умолчанию `public`) и версию.
3. Выберите нужные протоколы чекбоксами в левой панели.
4. Нажмите **«Сканировать»** и подтвердите предупреждение.
5. По завершении — **«Экспорт в CSV»**.

### Режим «Автообнаружение»

1. Поставьте галочку **«Автообнаружение (все интерфейсы)»** — поле подсети заблокируется, SNMP отключится, ARP и port scan включатся автоматически.
2. Нажмите **«Сканировать»**.

Поиск пройдёт по всем локальным подсетям (Wi-Fi + Ethernet) без перебора IP.

### Порядок работы протоколов

Приложение прогоняет протоколы последовательно:

1. **SNMP** (только по подсети, не в авторежиме)
2. **ARP ping sweep** — находит живые хосты
3. **TCP port scan** — уточняет тип устройства по открытым портам
4. **ONVIF WS-Discovery**
5. **SADP** (если включён и есть админ)
6. **Dahua**
7. **ISAPI probe** — финальный проход по всем найденным IP

Типичный прогон в режиме «Автообнаружение» на `/24` занимает **~25–30 секунд**.

### Прерывание

Кнопка **«Стоп»** активна во время сканирования. Уже найденные устройства остаются в таблице и попадают в CSV.

### Способы сканирования

Меню **Справка → Способы сканирования** открывает прокручиваемое описание всех семи протоколов: механизм, что находит, ограничения.

---

## 🏗️ Сборка `.exe`

### Один раз — из готового `CameraScanner.spec`

```bash
pyinstaller CameraScanner.spec --noconfirm
```

Готовый файл — `dist/CameraScanner.exe` (~40–60 МБ).

### Что включено в spec

- `--onefile` и `--windowed` (без консоли);
- иконка `assets/app.ico` — и в exe, и в бандле для `tkinter`;
- `hiddenimports` для `pysnmp` (иначе MIB'ы не попадут в exe и SNMP вернёт `NoSuchObject`);
- `collect_data_files("sv_ttk")` — ресурсы темы Sun Valley;
- `netifaces`, `darkdetect`, `wsdiscovery` — все нативные и опциональные модули.

### После пересборки иконка не обновилась в проводнике

Windows кэширует иконки по имени файла. Сбросьте:

```cmd
ie4uinit.exe -show
```

Или просто переименуйте exe.

---

## 📁 Структура проекта

```
CameraScanner/
├── main.py                 # GUI и точка входа
├── snmp_scanner.py         # SNMP-опрос (pysnmp 7.x, asyncio)
├── wsdiscovery_scanner.py  # ONVIF WS-Discovery (multicast + broadcast)
├── sadp_scanner.py         # SADP Hikvision (UDP multicast + broadcast)
├── dahua_scanner.py        # Dahua/Amcrest Discovery
├── arp_scanner.py          # ARP: ping sweep + чтение ARP-таблицы
├── port_scanner.py         # TCP port scan
├── isapi_scanner.py        # ISAPI probe (Hikvision HTTP)
├── net_utils.py            # Broadcast-адреса и локальные подсети
├── exporter.py             # Экспорт в CSV
├── assets/
│   └── app.ico             # Иконка (multi-size .ico, не PNG!)
├── CameraScanner.spec      # PyInstaller spec
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🩺 Troubleshooting

| Симптом | Причина | Решение |
|---|---|---|
| `ModuleNotFoundError: No module named 'pysnmp.hlapi'` | Пакет не установлен в venv, либо PyCharm использует другой интерпретатор | `pip install -r requirements.txt`; проверить **File → Settings → Project → Python Interpreter** |
| `Failed building wheel for netifaces` | Нет wheel для Python 3.12 / нет C++ Build Tools | Установить wheel от Odoo (см. выше) |
| `ModuleNotFoundError: No module named 'darkdetect'` | Пакет не установлен | `pip install darkdetect` |
| Иконка в exe старая / Python-перо | Кэш Explorer, либо `.ico` — переименованный PNG | `ie4uinit.exe -show`, проверить `certutil -dump assets\app.ico` |
| Камеры не находятся «Автообнаружением» | Multicast/broadcast не проходит через VLAN | Использовать режим «Подсеть» + SNMP |
| SADP ничего не находит | Нет прав администратора или брандмауэр блокирует UDP/37020 | Включить чекбокс SADP, согласиться на UAC, добавить exe в исключения firewall |
| SNMP возвращает `NoSuchObject` в exe | В spec не попал нужный MIB | Добавить имя в `hiddenimports` (`pysnmp.smi.mibs.IF-MIB`) и пересобрать |
| `_tkinter.TclError: invalid command name "…canvas"` при прокрутке | Старая версия с глобальным `bind_all("<MouseWheel>")` | Обновиться до v1.3.0 — там привязка колеса снимается при закрытии окна |
| `VCRUNTIME140.dll is missing` на другой машине | Отсутствует Visual C++ Redistributable | Установить [vc_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe) |
| Антивирус блокирует exe | Ложное срабатывание на `--onefile` | Отключить UPX в spec (`upx=False`), либо использовать `--onedir`, либо подписать код |

---

## 🗺️ Roadmap

- [ ] Асинхронный SNMP-опрос (сейчас последовательный — для `/24` занимает минуты)
- [ ] Индикатор прогресса (progress bar) для ARP/Port scan
- [ ] Фильтрация и сортировка таблицы по столбцам
- [ ] Сохранение и загрузка профилей сканирования
- [ ] Экспорт в JSON и XLSX
- [ ] Автоопределение модели по MAC (OUI lookup)
- [ ] Xiongmai / XMEye discovery (UDP broadcast)
- [ ] Поддержка SNMPv3 с полным GUI-диалогом (сейчас параметры v3 передаются через CLI)

---

## 🤝 Вклад

PR и issues приветствуются. Перед отправкой PR:

```bash
git status
```

`.venv/`, `build/`, `dist/`, `.idea/`, `*.csv` должны быть в `.gitignore`.

---

## 📜 Лицензия

Проект распространяется под лицензией **MIT** — см. файл [LICENSE](LICENSE).

---

## 👤 Автор

**Andrew Geben**
© 2026. Все права защищены.

---

<p align="center">
  <sub>Сделано с ❤️ для быстрой настройки видеонаблюдения</sub>
</p>