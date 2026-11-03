# экспорт в CSV
import csv

def export_to_csv(devices, filename="scan_results.csv"):
    """
    Экспортирует список словарей в CSV.
    Все ключи объединяются, отсутствующие значения заполняются пустыми строками.
    """
    if not devices:
        return

    # Собираем все возможные ключи
    fieldnames = set()
    for device in devices:
        fieldnames.update(device.keys())
    fieldnames = list(fieldnames)

    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)