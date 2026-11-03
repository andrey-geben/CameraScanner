# CameraScanner

> Утилита активного обнаружения IP-камер в локальной сети с современным GUI в стиле Windows 11.

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**CameraScanner** — настольное приложение для быстрого поиска IP-камер и сетевых видеорегистраторов в локальной сети. Поддерживает четыре независимых протокола обнаружения, работает как с явно заданной подсетью (перебор адресов), так и в режиме **«Автообнаружение»** — multicast/broadcast-поиск сразу во всём L2-сегменте, без указания маски.

---

## ✨ Возможности

| Протокол | Механизм | Что находит |
|---|---|---|
| **SNMP v1 / v2c / v3** | GET-запросы на UDP/161 | Устройства с открытым SNMP: MIB-II + вендорские OID Hikvision |
| **ONVIF WS-Discovery** | SOAP `Probe` на multicast `239.255.255.250:3702` + broadcast-фоллбэк | Любые ONVIF-совместимые камеры и NVR |
| **SADP (Hikvision)** | UDP multicast `239.255.255.250/.230:37020` + broadcast | Hikvision: серийник, MAC, модель, версия прошивки, статус активации |
| **Dahua / Amcrest** | UDP broadcast `:37810`, JSON | Dahua/Amcrest, включая устройства с отключённым ONVIF |

Дополнительно:

- 🖥️ **Современный интерфейс** на Sun Valley (тема Windows 11) с переключением светлая/тёмная.
- 🔒 **Запрос прав администратора по требованию** — только при включении SADP. Параметры формы сохраняются при перезапуске через UAC.
- 🛑 **Кнопка «Стоп»** — прерывает сканирование в любой момент с сохранением уже найденных результатов.
- 📊 **Экспорт в CSV** — все поля всех протоколов в одной таблице.
- 🎨 **Кастомная иконка** и диалог «О программе» с копирайтом.
- 📦 **Сборка в один `.exe`** через PyInstaller — без внешних зависимостей на машине пользователя.

---

## 🖼️ Скриншот

> *Добавьте сюда скриншот главного окна — перетащите картинку прямо в редактор GitHub.*

```
![Главное окно CameraScanner](docs/screenshot-main.png)
```

---

## 📋 Требования

- **ОС:** Windows 10 или Windows 11 (64-bit)
- **Python:** 3.12+
- **Сеть:** доступ в локальный сегмент, где находятся камеры (broadcast-домен)
- **Права:** обычные — для SNMP/ONVIF/Dahua; администратора — только для SADP

> ⚠️ **Multicast/broadcast не проходят через маршрутизатор.** Автообнаружение находит устройства только в том же L2-сегменте (VLAN). Для поиска за роутером используйте SNMP-перебор по подсети.

---

## 🚀 Установка

### 1. Клонирование и виртуальное окружение

```bash
git clone https://github.com/<ваш-логин>/CameraScanner.git
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

Либо поставьте галочку **«SADP (Hikvision)»** в интерфейсе — приложение само вызовет UAC и перезапустится с сохранением всех параметров. Либо запустите сразу:

```bash
python main.py --elevated
```

### Доступные аргументы CLI

| Аргумент | Назначение |
|---|---|
| `--elevated` | Маркер, что процесс уже запущен с правами администратора |
| `--subnet 192.168.1.0/24` | Предзаполнить подсеть |
| `--community public` | SNMP community |
| `--snmp-version v2c` | Версия SNMP: `v1`, `v2c`, `v3` |
| `--auto 0\|1` | Включить режим автообнаружения |
| `--snmp 0\|1` | Включить SNMP |
| `--onvif 0\|1` | Включить ONVIF |
| `--dahua 0\|1` | Включить Dahua |

Все аргументы используются внутренне при UAC-перезапуске и могут быть переданы вручную.

---

## 🖱️ Как пользоваться

### Режим «Подсеть»

1. Введите CIDR-нотацию подсети, например `192.168.1.0/24`.
2. Укажите SNMP community (по умолчанию `public`) и версию.
3. Выберите нужные протоколы чекбоксами.
4. Нажмите **«Сканировать»**.
5. По завершении — **«Экспорт в CSV»**.

### Режим «Автообнаружение»

1. Поставьте галочку **«Автообнаружение (без подсети)»** — поле подсети и SNMP-чекбокс заблокируются.
2. Убедитесь, что включены нужные multicast/broadcast-протоколы (ONVIF, SADP, Dahua).
3. Нажмите **«Сканировать»**.

Поиск пройдёт по всем сетевым интерфейсам сразу, без перебора IP-адресов. Обычно занимает 5–10 секунд.

### Прерывание

Кнопка **«Стоп»** активна во время сканирования. Уже найденные устройства остаются в таблице и попадают в CSV — даже при прерывании.

---

## 🏗️ Сборка `.exe`

### Один раз — из готового `CameraScanner.spec`

```bash
pyinstaller CameraScanner.spec --noconfirm
```

Готовый файл — `dist/CameraScanner.exe` (~40–60 МБ).

### Что уже включено в spec

- `--onefile` и `--windowed` (без консоли);
- иконка `assets/app.ico` — и в exe, и в бандле для `tkinter`;
- `hiddenimports` для `pysnmp` (иначе MIB'ы не попадут в exe и SNMP вернёт `NoSuchObject`);
- `collect_data_files("sv_ttk")` — ресурсы темы;
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
├── net_utils.py            # Список broadcast-адресов всех интерфейсов
├── exporter.py             # Экспорт в CSV
├── assets/
│   └── app.ico             # Иконка (multi-size .ico, не PNG!)
├── CameraScanner.spec      # PyInstaller spec
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🐛 Известные предупреждения

**`could not find handler for: _handle_probe`**

Появляется в консоли при работе ONVIF-поиска. Причина — некоторые недорогие камеры присылают в ответ на `Probe` сообщение с тем же `MessageId`, что и запрос, нарушая спецификацию WS-Discovery. Мы передаём `WSDiscovery(relates_to=True)`, что минимизирует предупреждение. Оно **безвредно** и не влияет на обнаружение.

---

## 🩺 Troubleshooting

| Симптом | Причина | Решение |
|---|---|---|
| `ModuleNotFoundError: No module named 'pysnmp.hlapi'` | Пакет не установлен в текущем venv, либо PyCharm использует другой интерпретатор | `pip install -r requirements.txt`; проверить **File → Settings → Project → Python Interpreter** |
| `Failed building wheel for netifaces` | Нет готового wheel для Python 3.12 / нет C++ Build Tools | Установить wheel от Odoo (см. выше) |
| `ModuleNotFoundError: No module named 'darkdetect'` | Пакет не установлен | `pip install darkdetect` |
| Иконка в exe старая / Python-перо | Кэш Explorer, либо `.ico` — переименованный PNG | `ie4uinit.exe -show`, проверить `certutil -dump assets\app.ico` (сигнатура `00 00 01 00`) |
| Камеры не находятся «Автообнаружением», но находятся по IP | Multicast/broadcast не проходит через VLAN/роутер | Использовать режим «Подсеть» + SNMP |
| SADP ничего не находит | Нет прав администратора или брандмауэр блокирует UDP/37020 | Включить чекбокс SADP, согласиться на UAC, добавить exe в исключения firewall |
| SNMP возвращает `NoSuchObject` в exe (но не в dev) | В spec не попал нужный MIB | Добавить имя в `hiddenimports` (`pysnmp.smi.mibs.IF-MIB`) и пересобрать |

---

## 🗺️ Roadmap

- [ ] Асинхронный SNMP-опрос (сейчас последовательный — для `/24` занимает минуты)
- [ ] Фильтрация и сортировка таблицы по столбцам
- [ ] Сохранение и загрузка профилей сканирования
- [ ] Экспорт в JSON и XLSX
- [ ] Автоматическое определение модели по MAC (OUI lookup)
- [ ] ICMP-проверка живости перед SNMP (снижает время сканирования)

---

## 🤝 Вклад

PR и issues приветствуются. Перед отправкой PR убедитесь, что не тащите артефакты сборки:

```bash
git status
```

`.venv/`, `build/`, `dist/`, `.idea/`, `*.csv` — должны быть в `.gitignore`.

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