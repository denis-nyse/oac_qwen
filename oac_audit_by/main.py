#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAC-Audit-BY: Автоматизированный сканер соответствия требованиям Приказа ОАЦ №66
Версия MVP 0.1.0 (Windows Edition)

Запуск:
    python main.py

Требования:
    - Python 3.9+
    - questionary
    - pyyaml
    - jinja2
"""

import sys
import ctypes
import questionary
from core.auditor import OACAuditor

def is_admin():
    """Проверка прав администратора (для Windows)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        # Если не Windows, считаем что права есть (для тестов на Linux)
        return True

def main():
    print("=" * 60)
    print("OAC-Audit-BY: Сканер соответствия Приказу ОАЦ №66")
    print("Версия MVP 0.1.0")
    print("=" * 60)

    # Проверка прав администратора
    if not is_admin():
        print("\n[ПРЕДУПРЕЖДЕНИЕ] Скрипт запущен БЕЗ прав администратора!")
        print("Некоторые проверки могут не работать корректно.")
        print("Рекомендуется перезапустить скрипт от имени Администратора.\n")
        
        cont = questionary.confirm("Продолжить без прав администратора?", default=False).ask()
        if not cont:
            print("Завершен пользователем.")
            sys.exit(0)

    # Множественный выбор классов ИС
    oac_classes = questionary.checkbox(
        "Выберите классы типовых ИС (Пробел - выбор, Enter - подтвердить):",
        choices=[
            "4-ин", "4-спец", "4-бг", "4-юл", "4-дсп",
            "3-ин", "3-спец", "3-бг", "3-юл", "3-дсп"
        ],
        validate=lambda x: "Выберите минимум один класс!" if len(x) == 0 else True
    ).ask()

    if not oac_classes:
        print("Выбор классов отменен. Завершение работы.")
        sys.exit(0)

    print(f"\nВыбраны классы ИС: {', '.join(oac_classes)}")
    print("Запуск аудита...\n")

    # Инициализация и запуск аудитора
    auditor = OACAuditor()
    auditor.run(oac_classes)

if __name__ == "__main__":
    main()
