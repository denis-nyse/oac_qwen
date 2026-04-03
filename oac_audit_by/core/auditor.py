import os
import sys
import yaml
import socket
import logging
import subprocess
import re
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Настройка логирования
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
log_file = LOG_DIR / f"oac_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class OACAuditor:
    def __init__(self):
        self.config_dir = Path(__file__).parent.parent / "config"
        self.rules = []
        self.szi_templates = []
        self.selected_classes = []
        self.results_os = []
        self.results_szi = []
        self.hostname = socket.gethostname()
        try:
            self.username = os.getlogin()
        except Exception:
            self.username = os.environ.get('USERNAME', os.environ.get('USER', 'Unknown'))

    def load_config(self):
        """Загрузка конфигурационных файлов YAML"""
        logger.info("Загрузка конфигурации...")
        
        # Загрузка правил
        rules_file = self.config_dir / "rules.yaml"
        if not rules_file.exists():
            logger.error(f"Файл правил не найден: {rules_file}")
            return False
        
        with open(rules_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            self.rules = data.get('rules', [])
        logger.info(f"Загружено правил: {len(self.rules)}")

        # Загрузка шаблонов СЗИ
        szi_file = self.config_dir / "szi_templates.yaml"
        if not szi_file.exists():
            logger.warning(f"Файл шаблонов СЗИ не найден: {szi_file}")
            self.szi_templates = []
        else:
            with open(szi_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                self.szi_templates = data.get('szi_checks', [])
            logger.info(f"Загружено шаблонов СЗИ: {len(self.szi_templates)}")
        
        return True

    def filter_rules(self, selected_classes):
        """Фильтрация правил по выбранным классам ИС"""
        self.selected_classes = selected_classes
        filtered_rules = []
        for rule in self.rules:
            mandatory = rule.get('mandatory_classes', [])
            # Если хотя бы один выбранный класс есть в списке обязательных для правила
            if any(cls in mandatory for cls in selected_classes):
                filtered_rules.append(rule)
        
        logger.info(f"Отфильтровано правил для классов {selected_classes}: {len(filtered_rules)}")
        self.rules = filtered_rules

    def execute_command(self, shell, args):
        """Выполнение команды с возвратом вывода"""
        try:
            # Для MVP предполагаем локальный запуск
            cmd = [shell] + args
            logger.debug(f"Выполнение команды: {' '.join(cmd)}")
            
            # Обработка для Windows (подразумевается запуск на Windows)
            # В Linux этот код будет выдавать ошибки, что ожидаемо для MVP
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=(shell == 'cmd')
            )
            
            output = result.stdout + result.stderr
            return output, result.returncode == 0
        except FileNotFoundError:
            return f"Команда не найдена: {shell}", False
        except Exception as e:
            logger.error(f"Ошибка выполнения команды: {e}")
            return str(e), False

    def parse_result(self, output, pattern, check_type):
        """Парсинг результата команды"""
        match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        if not match:
            return None
        
        value = match.group(1) if match.lastindex >= 1 else match.group(0)
        
        if check_type == 'numeric_compare':
            try:
                return int(value)
            except ValueError:
                return None
        elif check_type == 'boolean_false':
            return value.lower() in ['false', 'no', 'disabled']
        elif check_type == 'string_contains':
            return value
            
        return value

    def check_rule(self, rule):
        """Выполнение одной проверки с fallback"""
        rule_id = rule['id']
        description = rule['description']
        check_type = rule['check_type']
        expected = rule['expected_value']
        operator = rule.get('operator', '==')
        
        commands = rule.get('commands', {})
        primary = commands.get('primary')
        fallback = commands.get('fallback')
        
        actual_value = None
        success = False
        
        # Попытка 1: Основная команда
        if primary:
            output, ok = self.execute_command(primary['shell'], primary['args'])
            if ok:
                actual_value = self.parse_result(output, rule.get('parse_pattern', '(.*)'), check_type)
                if actual_value is not None:
                    success = True
                    logger.info(f"[{rule_id}] Основная команда успешна: {actual_value}")
        
        # Попытка 2: Fallback
        if not success and fallback:
            logger.warning(f"[{rule_id}] Основная команда неудачна, пробуем fallback...")
            output, ok = self.execute_command(fallback['shell'], fallback['args'])
            if ok:
                actual_value = self.parse_result(output, rule.get('parse_pattern', '(.*)'), check_type)
                if actual_value is not None:
                    success = True
                    logger.info(f"[{rule_id}] Fallback команда успешна: {actual_value}")
        
        if not success:
            logger.error(f"[{rule_id}] Не удалось получить значение")
            return {
                'id': rule_id,
                'description': description,
                'expected': str(expected),
                'actual': 'Не удалось определить',
                'status_class': 'error',
                'status_text': 'Ошибка проверки'
            }

        # Сравнение
        is_compliant = False
        if check_type == 'numeric_compare':
            if operator == '>=': is_compliant = actual_value >= expected
            elif operator == '<=': is_compliant = actual_value <= expected
            elif operator == '==': is_compliant = actual_value == expected
        elif check_type == 'boolean_false':
            is_compliant = (actual_value == expected)
        elif check_type == 'string_contains':
            is_compliant = expected in str(actual_value)
        
        status_class = 'pass' if is_compliant else 'fail'
        status_text = 'Соответствует' if is_compliant else 'Не соответствует'
        
        logger.info(f"[{rule_id}] Результат: {status_text} (Факт: {actual_value}, Ожидание: {expected})")
        
        return {
            'id': rule_id,
            'description': description,
            'expected': f"{operator} {expected}" if check_type == 'numeric_compare' else str(expected),
            'actual': str(actual_value),
            'status_class': status_class,
            'status_text': status_text
        }

    def check_szi(self, szi_template):
        """Проверка наличия СЗИ"""
        name = szi_template['name']
        desc = szi_template['description']
        paths = szi_template.get('paths', [])
        service_name = szi_template.get('service_name')
        
        found = False
        details = []
        
        # Проверка путей
        for path in paths:
            if os.path.exists(path):
                found = True
                details.append(f"Файл найден: {path}")
                logger.info(f"[СЗИ] {name}: Найден файл {path}")
            else:
                details.append(f"Файл не найден: {path}")
        
        # Проверка службы (упрощенно через sc query для Windows)
        if service_name and not found:
            try:
                result = subprocess.run(['sc', 'query', service_name], capture_output=True, text=True)
                if result.returncode == 0 and 'RUNNING' in result.stdout:
                    found = True
                    details.append(f"Служба активна: {service_name}")
                    logger.info(f"[СЗИ] {name}: Служба {service_name} активна")
                else:
                    details.append(f"Служба не активна: {service_name}")
            except Exception as e:
                details.append(f"Ошибка проверки службы: {e}")
        
        status_class = 'pass' if found else 'fail'
        status_text = 'Найдено' if found else 'Не найдено'
        
        return {
            'name': name,
            'description': desc,
            'details': '; '.join(details),
            'status_class': status_class,
            'status_text': status_text
        }

    def generate_report(self):
        """Генерация HTML отчета"""
        logger.info("Генерация отчета...")
        
        template_dir = Path(__file__).parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html.j2")
        
        html_content = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            hostname=self.hostname,
            username=self.username,
            selected_classes=self.selected_classes,
            os_checks=self.results_os,
            szi_checks=self.results_szi
        )
        
        report_dir = Path(__file__).parent.parent / "reports"
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f"OAC_Report_{self.hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Отчет сохранен: {report_file}")
        return report_file

    def run(self, selected_classes):
        """Основной метод запуска аудита"""
        if not self.load_config():
            return
        
        self.filter_rules(selected_classes)
        
        # Выполнение проверок ОС
        logger.info("Начало проверок настроек ОС...")
        for rule in self.rules:
            result = self.check_rule(rule)
            self.results_os.append(result)
        
        # Выполнение проверок СЗИ
        logger.info("Начало проверок СЗИ...")
        # В MVP проверяем все шаблоны, если они релевантны выбранным классам
        for szi in self.szi_templates:
            szi_classes = szi.get('mandatory_classes', [])
            if not szi_classes or any(cls in szi_classes for cls in selected_classes):
                result = self.check_szi(szi)
                self.results_szi.append(result)
        
        # Генерация отчета
        report_path = self.generate_report()
        print(f"\n{'='*50}")
        print(f"Аудит завершен. Отчет сохранен: {report_path}")
        print(f"{'='*50}")
