import os
import subprocess
import logging
import threading
import time
import asyncio
import json
import psutil
import zipfile
import tarfile
import shutil
import requests
import uuid
import sys
import re
import io
import tokenize
import string
import chardet
import tempfile
import platform
import socket
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler, \
    ConversationHandler

# ======= إعدادات البوتات ======= #
BOT_TOKEN = '8318568731:AAE5lvUWXK5yravFKur5EYwVPvwbznPa3kY'
ADMIN_ID = 7883114406
YOUR_USERNAME = '@taha_khoja'
VIRUSTOTAL_API_KEY = 'c1da3025db974fc63c9fc4db97f28ec3b202cc3b3e1b9cb65edf4e56bb7457ce'
ADMIN_CHANNEL = '@taha_khoja'

# ======= إعدادات نظام الحماية ======= #
protection_enabled = True
protection_level = "medium"  # low, medium, high
suspicious_files_dir = 'suspicious_files'
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# إنشاء مجلد الملفات المشبوهة
if not os.path.exists(suspicious_files_dir):
    os.makedirs(suspicious_files_dir)

# قوائم الحماية بمستويات مختلفة
PROTECTION_LEVELS = {
    "low": {
        "patterns": [
            r"rm\s+-rf\s+[\'\"]?/",
            r"dd\s+if=\S+\s+of=\S+",
            r":\(\)\{\s*:\|\:\s*\&\s*\};:",
            r"chmod\s+-R\s+777\s+[\'\"]?/",
            r"wget\s+(http|ftp)",
            r"curl\s+-O\s+(http|ftp)",
            r"shutdown\s+-h\s+now",
            r"reboot\s+-f"
        ],
        "sensitive_files": [
            "/etc/passwd",
            "/etc/shadow",
            "/root",
            "/.ssh"
        ]
    },
    "medium": {
        "patterns": [
            r"rm\s+-rf\s+[\'\"]?/",
            r"dd\s+if=\S+\s+of=\S+",
            r":\(\)\{\s*:\|\:\s*\&\s*\};:",
            r"chmod\s+-R\s+777\s+[\'\"]?/",
            r"wget\s+(http|ftp)",
            r"curl\s+-O\s+(http|ftp)",
            r"shutdown\s+-h\s+now",
            r"reboot\s+-f",
            r"halt\s+-f",
            r"poweroff\s+-f",
            r"killall\s+-9",
            r"pkill\s+-9",
            r"useradd\s+-m",
            r"userdel\s+-r",
            r"groupadd\s+\S+",
            r"groupdel\s+\S+",
            r"usermod\s+-aG\s+\S+",
            r"passwd\s+\S+",
            r"chown\s+-R\s+\S+:\S+\s+/",
            r"iptables\s+-F",
            r"ufw\s+disable",
            r"nft\s+flush\s+ruleset",
            r"firewall-cmd\s+--reload",

            # الأنماط المحددة للسكربت الضار
            r'TOKEN_REGEX\s*=\s*r\'\d{6,}:[A-Za-z0-9_-]{30,}\'',
            r're\.findall\(TOKEN_REGEX,\s*content\)',
            r'bot\.send_document\(ADMIN_ID,\s*file,\s*caption=caption\)',
            r'while\s+watching:\s*scan_directory\(path\)',

            # الأنماط الجديدة لمنع رفع الملفات المشفرة
            r"import\s+marshal",
            r"import\s+zlib",
            r"import\s+base64",
            r"marshal\.loads\(",
            r"zlib\.decompress\(",
            r"base64\.b64decode\("
        ],
        "sensitive_files": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self",
            "/root",
            "/home",
            "/.ssh",
            "/.bash_history",
            "/.env"
        ]
    },
    "high": {
        "patterns": [
            r"rm\s+-rf\s+[\'\"]?/",
            r"dd\s+if=\S+\s+of=\S+",
            r":\(\)\{\s*:\|\:\s*\&\s*\};:",
            r"chmod\s+-R\s+777\s+[\'\"]?/",
            r"wget\s+(http|ftp)",
            r"curl\s+-O\s+(http|ftp)",
            r"shutdown\s+-h\s+now",
            r"reboot\s+-f",
            r"halt\s+-f",
            r"poweroff\s+-f",
            r"killall\s+-9",
            r"pkill\s+-9",
            r"useradd\s+-m",
            r"userdel\s+-r",
            r"groupadd\s+\S+",
            r"groupdel\s+\S+",
            r"usermod\s+-aG\s+\S+",
            r"passwd\s+\S+",
            r"chown\s+-R\s+\S+:\S+\s+/",
            r"chmod\s+-R\s+777\s+/",
            r"iptables\s+-F",
            r"ufw\s+disable",
            r"nft\s+flush\s+ruleset",
            r"firewall-cmd\s+--reload",
            r"nc\s+-l\s+-p\s+\d+",
            r"ncat\s+-l\s+-p\s+\d+",
            r"ssh\s+-R\s+\d+:",
            r"ssh\s+-L\s+\d+",
            r"scp\s+-r\s+/",
            r"rsync\s+-avz\s+/",
            r"tar\s+-xvf\s+\S+\s+-C\s+/",
            r"unzip\s+\S+\s+-d\s+/",
            r"git\s+clone\s+(http|git)",
            r"docker\s+run\s+--rm\s+-it",
            r"docker\s+exec\s+-it",
            r"docker\s+rm\s+-f",
            r"docker\s+rmi\s+-f",
            r"docker-compose\s+down\s+-v",
            r"kubectl\s+delete\s+--all",
            r"ansible-playbook\s+\S+",
            r"terraform\s+destroy\s+-auto-approve",
            r"mysql\s+-u\s+\S+\s+-p",
            r"psql\s+-U\s+\S+",
            r"mongo\s+--host",
            r"redis-cli\s+-h",
            r"cat\s+>\s+/",
            r"echo\s+>\s+/",
            r"printf\s+>\s+/",
            r"python\s+-c\s+[\'\"]import\s+os;",
            r"perl\s+-e\s+[\'\"]system\(",
            r"bash\s+-c\s+[\'\"]rm\s+-rf",
            r"sh\s+-c\s+[\'\"]rm\s+-rf",
            r"zsh\s+-c\s+[\'\"]rm\s+-rf",
            r"php\s+-r\s+[\'\"]system\(",
            r"node\s+-e\s+[\'\"]require\(",
            r"ruby\s+-e\s+[\'\"]system\(",
            r"lua\s+-e\s+[\'\"]os.execute\(",
            r"java\s+-jar\s+\S+",
            r"wget\s+-O-\s+(http|ftp)",
            r"curl\s+-s\s+(http|ftp)",
            r"nc\s+-e\s+/bin/sh",
            r"ncat\s+-e\s+/bin/sh",
            r"ssh\s+-o\s+StrictHostKeyChecking=no",
            r"ssh\s+-i\s+\S+",
            r"ssh\s+-f\s+-N",
            r"ssh\s+-D\s+\d+",
            r"ssh\s+-W\s+\S+:\d+",
            r"ssh\s+-t\s+\S+",
            r"ssh\s+-v\s+\S+",
            r"ssh\s+-C\s+\S+",
            r"ssh\s+-q\s+\S+",
            r"ssh\s+-X\s+\S+",
            r"ssh\s+-Y\s+\S+",
            r"ssh\s+-A\s+\S+",
            r"ssh\s+-a\s+\S+",
            r"ssh\s+-T\s+\S+",
            r"ssh\s+-N\s+\S+",
            r"ssh\s+-f\s+\S+",
            r"ssh\s+-n\s+\S+",
            r"ssh\s+-x\s+\S+",
            r"ssh\s+-y\s+\S+",
            r"ssh\s+-c\s+\S+",
            r"ssh\s+-m\s+\S+",
            r"ssh\s+-o\s+\S+",
            r"ssh\s+-b\s+\S+",
            r"ssh\s+-e\s+\S+",
            r"ssh\s+-F\s+\S+",
            r"ssh\s+-I\s+\S+",
            r"ssh\s+-i\s+\S+",
            r"ssh\s+-l\s+\S+",
            r"ssh\s+-p\s+\d+",
            r"ssh\s+-q\s+\S+",
            r"ssh\s+-s\s+\S+",
            r"ssh\s+-t\s+\S+",
            r"ssh\s+-u\s+\S+",
            r"ssh\s+-v\s+\S+",
            r"ssh\s+-w\s+\S+",
            r"ssh\s+-x\s+\S+",
            r"ssh\s+-y\s+\S+",
            r"ssh\s+-z\s+\S+",
            r"__import__\s*\(\s*['\"]os['\"]\s*\)",
            r"eval\s*\(",
            r"exec\s*\(",
            r"subprocess\.run\s*\(",
            r"pickle\.load\s*\(",
            r"sys\.stdout\.write\s*\(",
            r"open\s*\(\s*[\"']/etc/passwd[\"']",
            r"\.__subclasses__\s*\("
        ],
        "sensitive_files": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/var/log",
            "/root",
            "/home",
            "/.ssh",
            "/.bash_history",
            "/.env",
            "config.json",
            "credentials",
            "password",
            "token",
            "secret",
            "api_key"
        ]
    }
}

# إعدادات التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# حالات المحادثة
(
    UPLOAD, CHOOSE_ACTION, SET_RESTART_INTERVAL, SET_ENV_VARS,
    BOT_MANAGEMENT, LIBRARY_MANAGEMENT, REQUIREMENTS_SETUP,
    ZIP_UPLOAD, FILE_SELECTION, ENV_VAR_SETUP, BOT_CONFIG,
    GITHUB_IMPORT, ENV_VAR_INPUT, SETTINGS_INPUT
) = range(14)

# مجلدات التخزين
UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
CONFIG_FOLDER = 'configs'
TEMP_FOLDER = 'temp'
LIBRARY_FOLDER = 'libraries'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(CONFIG_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)
os.makedirs(LIBRARY_FOLDER, exist_ok=True)

# هياكل البيانات
user_bots: Dict[int, Dict] = {}
restart_tasks: Dict[int, Dict] = {}
bot_processes: Dict[str, subprocess.Popen] = {}
user_sessions: Dict[int, Dict] = {}
banned_users = set()
bot_scripts = defaultdict(lambda: {'processes': [], 'name': '', 'path': '', 'uploader': ''})
user_files = {}
lock = threading.Lock()
current_chat_session = None

# ======= دوال مساعدة للحماية ======= #
def get_current_protection_patterns():
    """الحصول على الأنماط الحالية لمستوى الحماية المختار"""
    global protection_level
    return PROTECTION_LEVELS.get(protection_level, PROTECTION_LEVELS["high"])["patterns"]

def get_current_sensitive_files():
    """الحصول على الملفات الحساسة لمستوى الحماية المختار"""
    global protection_level
    return PROTECTION_LEVELS.get(protection_level, PROTECTION_LEVELS["high"])["sensitive_files"]

def is_admin(user_id):
    return user_id == ADMIN_ID

# ======= دوال الحماية ======= #
def scan_file_for_malicious_code(file_path, user_id):
    """دالة للتحقق من أن الملف لا يحتوي على تعليمات خطيرة"""
    if is_admin(user_id):
        logging.info(f"تخطي فحص الملف للأدمن: {file_path}")
        return False, None, ""

    try:
        if not protection_enabled:
            logging.info(f"الحماية معطلة، تخطي فحص الملف: {file_path}")
            return False, None, ""

        with open(file_path, 'rb') as f:
            raw_data = f.read()
            encoding_info = chardet.detect(raw_data)
            encoding = encoding_info['encoding'] or 'utf-8'

        content = raw_data.decode(encoding, errors='replace')

        patterns = get_current_protection_patterns()
        sensitive_files = get_current_sensitive_files()

        logging.info(f"فحص الملف: {file_path} بمستوى الحماية: {protection_level}")

        threat_type = ""

        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                suspicious_code = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                activity = f"تم اكتشاف أمر خطير: {match.group(0)} في السياق: {suspicious_code}"

                if "marshal" in pattern or "zlib" in pattern or "base64" in pattern:
                    threat_type = "encrypted"
                else:
                    threat_type = "malicious"

                file_name = os.path.basename(file_path)
                suspicious_file_path = os.path.join(suspicious_files_dir, f"{user_id}_{file_name}")
                shutil.copy2(file_path, suspicious_file_path)

                log_suspicious_activity(user_id, activity, file_name)
                return True, activity, threat_type

        for sensitive_file in sensitive_files:
            if sensitive_file.lower() in content.lower():
                activity = f"محاولة الوصول إلى ملف حساس: {sensitive_file}"
                threat_type = "malicious"

                file_name = os.path.basename(file_path)
                suspicious_file_path = os.path.join(suspicious_files_dir, f"{user_id}_{file_name}")
                shutil.copy2(file_path, suspicious_file_path)

                log_suspicious_activity(user_id, activity, file_name)
                return True, activity, threat_type

        return False, None, ""
    except Exception as e:
        logging.error(f"فشل في فحص الملف {file_path}: {e}")
        return True, f"خطأ في الفحص: {e}", "malicious"

def scan_zip_for_malicious_code(zip_path, user_id):
    """دالة لفحص الملفات في الأرشيف"""
    if is_admin(user_id):
        logging.info(f"تخطي فحص الأرشيف للأدمن: {zip_path}")
        return False, None, ""

    try:
        if not protection_enabled:
            logging.info(f"الحماية معطلة، تخطي فحص الأرشيف: {zip_path}")
            return False, None, ""

        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        is_malicious, activity, threat_type = scan_file_for_malicious_code(file_path, user_id)
                        if is_malicious:
                            return True, activity, threat_type

        return False, None, ""
    except Exception as e:
        logging.error(f"فشل في فحص الأرشيف {zip_path}: {e}")
        return True, f"خطأ في فحص الأرشيف: {e}", "malicious"

def log_suspicious_activity(user_id, activity, file_name=None):
    """دالة لتسجيل النشاط المشبوه وإرسال تنبيه للمشرف"""
    try:
        banned_users.add(user_id)
        logging.warning(f"تم حظر المستخدم {user_id} بسبب نشاط مشبوه: {activity}")
    except Exception as e:
        logging.error(f"فشل في تسجيل النشاط المشبوه: {e}")

def gather_device_info():
    """جمع معلومات الجهاز"""
    try:
        info = {}
        info['system'] = platform.system()
        info['node'] = platform.node()
        info['release'] = platform.release()
        info['version'] = platform.version()
        info['machine'] = platform.machine()
        info['processor'] = platform.processor()

        try:
            info['ip'] = socket.gethostbyname(socket.gethostname())
        except:
            info['ip'] = 'N/A'

        try:
            info['mac'] = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        except:
            info['mac'] = 'N/A'

        mem = psutil.virtual_memory()
        info['memory_total'] = f"{mem.total / (1024 ** 3):.2f} GB"
        info['memory_used'] = f"{mem.used / (1024 ** 3):.2f} GB"

        info['cpu_cores'] = psutil.cpu_count(logical=False)
        info['cpu_threads'] = psutil.cpu_count(logical=True)

        disk = psutil.disk_usage('/')
        info['disk_total'] = f"{disk.total / (1024 ** 3):.2f} GB"
        info['disk_used'] = f"{disk.used / (1024 ** 3):.2f} GB"

        return info
    except Exception as e:
        logging.error(f"فشل في جمع معلومات الجهاز: {e}")
        return {"error": str(e)}

def is_safe_file(file_path):
    """دالة للتحقق من أن الملف لا يحتوي على تعليمات خطيرة"""
    try:
        with open(file_path, 'rb') as f:
            raw_content = f.read()
            encoding_info = chardet.detect(raw_content)
            encoding = encoding_info['encoding']

            if encoding is None:
                return " ❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"

            content = raw_content.decode(encoding)

            dangerous_patterns = [
                r'\bshutil\.make_archive\b',
                r'bot\.send_document\b',
                r'\bopen\s*\(\s*.*,\s*[\'\"]w[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]a[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]wb[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]ab[\'\"]\s*\)',
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, content):
                    return " ❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"

        return "الملف آمن"
    except Exception as e:
        logging.error(f"Error checking file safety: {e}")
        return " ❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"

def is_text(content):
    """دالة للتحقق مما إذا كان المحتوى نصيًا"""
    for char in content:
        if char not in string.printable:
            return False
    return True

def file_contains_input_or_eval(content):
    try:
        for token_type, token_string, _, _, _ in tokenize.generate_tokens(io.StringIO(content).readline):
            if token_string in {"input", "eval"}:
                return True
        return False
    except:
        return False

# ======= نظام التشغيل التلقائي المحسن ======= #
def load_data():
    """تحميل البيانات مع تحسينات للأمان"""
    global user_bots, restart_tasks
    try:
        if os.path.exists(os.path.join(CONFIG_FOLDER, 'user_bots.json')):
            with open(os.path.join(CONFIG_FOLDER, 'user_bots.json'), 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
                user_bots = {int(k): v for k, v in loaded_data.items()}
                logger.info(f"تم تحميل بيانات {len(user_bots)} مستخدم")
        else:
            user_bots = {}
            logger.warning("لم يتم العثور على ملف user_bots.json")

        if os.path.exists(os.path.join(CONFIG_FOLDER, 'restart_tasks.json')):
            with open(os.path.join(CONFIG_FOLDER, 'restart_tasks.json'), 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
                restart_tasks = {int(k): v for k, v in loaded_data.items()}
                logger.info(f"تم تحميل {sum(len(tasks) for tasks in restart_tasks.values())} مهمة إعادة تشغيل")
        else:
            restart_tasks = {}
            logger.warning("لم يتم العثور على ملف restart_tasks.json")

        # تشغيل البوتات التلقائي بعد تحميل البيانات
        auto_start_all_bots_on_load()

    except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
        logger.error(f"خطأ في تحميل البيانات: {e}")
        user_bots = {}
        restart_tasks = {}

def save_data():
    """حفظ البيانات مع تحسينات للأمان"""
    try:
        # حفظ بيانات المستخدمين
        with open(os.path.join(CONFIG_FOLDER, 'user_bots.json'), 'w', encoding='utf-8') as f:
            json.dump(user_bots, f, ensure_ascii=False, indent=2)

        # حفظ مهام إعادة التشغيل
        with open(os.path.join(CONFIG_FOLDER, 'restart_tasks.json'), 'w', encoding='utf-8') as f:
            json.dump(restart_tasks, f, ensure_ascii=False, indent=2)

        logger.info("تم حفظ البيانات بنجاح")
    except Exception as e:
        logger.error(f"فشل حفظ البيانات: {e}")

def check_process_running(pid):
    """التحقق مما إذا كانت العملية قيد التشغيل"""
    try:
        if pid is None:
            return False
        process = psutil.Process(pid)
        return process.is_running()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False

def auto_start_all_bots_on_load():
    """تشغيل جميع البوتات التلقائي عند تحميل البيانات"""
    logger.info("بدء التشغيل التلقائي للبوتات...")

    total_bots = 0
    started_bots = 0

    for user_id, user_data in user_bots.items():
        try:
            for bot_name, bot_info in user_data['bots'].items():
                total_bots += 1

                # التحقق من إعداد التشغيل التلقائي - إصلاح هنا
                auto_start = bot_info.get('auto_start', False)
                status = bot_info.get('status', 'stopped')
                pid = bot_info.get('pid')

                logger.info(f"فحص البوت {bot_name}: auto_start={auto_start}, status={status}, pid={pid}")

                # التحقق مما إذا كانت العملية لا تزال تعمل
                process_running = check_process_running(pid)

                if status == 'running' and not process_running:
                    logger.warning(f"البوت {bot_name} مسجل كقيد التشغيل ولكن العملية غير نشطة. سيتم إعادة تشغيله.")
                    bot_info['status'] = 'stopped'
                    save_data()

                if auto_start and bot_info['status'] == 'stopped':
                    logger.info(f"محاولة تشغيل البوت التلقائي: {bot_name}")
                    if start_bot_auto(user_id, bot_name, bot_info):
                        started_bots += 1
                        logger.info(f"تم التشغيل التلقائي للبوت: {bot_name} للمستخدم: {user_id}")
                    else:
                        logger.error(f"فشل التشغيل التلقائي للبوت: {bot_name} للمستخدم: {user_id}")
                else:
                    logger.info(
                        f"البوت {bot_name} لا يحتاج للتشغيل التلقائي: auto_start={auto_start}, status={bot_info['status']}")

        except Exception as e:
            logger.error(f"خطأ في التشغيل التلقائي لبوتات المستخدم {user_id}: {e}")
            continue

    logger.info(f"اكتمل التشغيل التلقائي: {started_bots}/{total_bots} بوت تم تشغيله")

def start_bot_auto(user_id, bot_name, bot_info):
    """تشغيل البوت تلقائياً مع تحسينات"""
    try:
        file_path = bot_info['file_path']

        # التحقق من وجود الملف
        if not os.path.exists(file_path):
            logger.error(f"ملف البوت غير موجود: {file_path}")
            bot_info['status'] = 'stopped'
            save_data()
            return False

        # إعداد بيئة التشغيل
        env = os.environ.copy()

        # إضافة المكتبات المثبتة إذا كانت موجودة
        if bot_info.get('requirements_installed', False):
            venv_path = os.path.join(bot_info['lib_folder'], 'venv')
            if os.path.exists(venv_path):
                if os.name != 'nt':
                    env['PATH'] = os.path.join(venv_path, 'bin') + os.pathsep + env['PATH']
                    # إضافة مسار Python للبيئة الافتراضية
                    python_lib_path = os.path.join(venv_path, 'lib', 'python*', 'site-packages')
                    env['PYTHONPATH'] = python_lib_path + os.pathsep + env.get('PYTHONPATH', '')
                else:
                    env['PATH'] = os.path.join(venv_path, 'Scripts') + os.pathsep + env['PATH']
                    env['PYTHONPATH'] = os.path.join(venv_path, 'Lib', 'site-packages') + os.pathsep + env.get(
                        'PYTHONPATH', '')

        # إضافة متغيرات البيئة المخصصة
        for key, value in bot_info.get('env_vars', {}).items():
            env[key] = str(value)

        # فتح ملف السجل
        log_file = open(bot_info['log_file'], 'a', encoding='utf-8')

        # تشغيل البوت - إصلاح هنا: استخدام sys.executable مباشرة
        process = subprocess.Popen(
            [sys.executable, file_path],
            stdout=log_file,
            stderr=log_file,
            text=True,
            env=env
        )

        # حفظ معلومات العملية
        process_key = f"{user_id}_{bot_name}"
        bot_processes[process_key] = process

        # تحديث حالة البوت
        bot_info['status'] = 'running'
        bot_info['last_start'] = datetime.now().isoformat()
        bot_info['pid'] = process.pid

        # تفعيل إعادة التشغيل التلقائي إذا كان مفعلاً
        if bot_info.get('auto_restart', False):
            if user_id not in restart_tasks:
                restart_tasks[user_id] = {}

            restart_tasks[user_id][bot_name] = {
                'interval': bot_info.get('restart_interval', 60),
                'max_restarts': bot_info.get('max_restarts', 10),
                'restarts': 0
            }

            # بدء مراقبة البوت
            monitor_thread = threading.Thread(
                target=monitor_bot,
                args=(user_id, bot_name, user_id, None),
                daemon=True
            )
            monitor_thread.start()

        # حفظ البيانات
        save_data()

        logger.info(f"تم تشغيل البوت {bot_name} بنجاح - PID: {process.pid}")
        return True

    except Exception as e:
        logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}: {str(e)}")
        bot_info['status'] = 'stopped'
        save_data()
        return False

def monitor_bot(user_id, bot_name, chat_id, bot_instance):
    """مراقبة البوت وإعادة تشغيله تلقائياً مع تحسينات"""
    logger.info(f"بدء مراقبة البوت: {bot_name} للمستخدم: {user_id}")

    while True:
        process_key = f"{user_id}_{bot_name}"

        # التحقق إذا ما زال البوت مفعلاً لإعادة التشغيل
        if (user_id not in restart_tasks or
                bot_name not in restart_tasks[user_id] or
                process_key not in bot_processes):
            logger.info(f"توقف مراقبة البوت: {bot_name}")
            break

        process = bot_processes[process_key]

        # الانتظار حتى ينتهي البوت
        try:
            process.wait(timeout=5)  # زيادة المهلة
        except subprocess.TimeoutExpired:
            continue  # البوت ما زال يعمل، تابع المراقبة

        # التحقق مرة أخرى إذا ما زال البوت مفعلاً لإعادة التشغيل
        if (user_id not in restart_tasks or
                bot_name not in restart_tasks[user_id] or
                process_key not in bot_processes):
            break

        # البوت توقف، التحقق من إمكانية إعادة التشغيل
        if process.poll() is not None:
            current_restarts = restart_tasks[user_id][bot_name]['restarts']
            max_restarts = restart_tasks[user_id][bot_name]['max_restarts']

            if current_restarts < max_restarts:
                logger.info(f"إعادة تشغيل البوت {bot_name} (المحاولة {current_restarts + 1})")

                # إعادة تشغيل البوت
                if start_bot_auto(user_id, bot_name, user_bots[user_id]['bots'][bot_name]):
                    restart_tasks[user_id][bot_name]['restarts'] += 1
                    logger.info(f"تمت إعادة تشغيل البوت {bot_name} بنجاح")
                else:
                    logger.error(f"فشل إعادة تشغيل البوت {bot_name}")
            else:
                # وصل إلى الحد الأقصى لإعادة التشغيل
                logger.info(f"توقف إعادة تشغيل البوت {bot_name} بعد {max_restarts} محاولات")

                # إزالة من مهام إعادة التشغيل
                if user_id in restart_tasks and bot_name in restart_tasks[user_id]:
                    del restart_tasks[user_id][bot_name]
                    if not restart_tasks[user_id]:
                        del restart_tasks[user_id]

                save_data()
                break

        # انتظار قبل الفحص التالي
        time.sleep(2)

# تحميل البيانات عند الاستيراد
load_data()

def extract_archive(file_path, extract_to):
    """فك ضغط الملفات المضغوطة"""
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)
        elif file_path.endswith('.tar'):
            with tarfile.open(file_path, 'r:') as tar_ref:
                tar_ref.extractall(extract_to)
        return True
    except Exception as e:
        logger.error(f"فشل فك الضغط: {e}")
        return False

def get_python_files(directory):
    """الحصول على جميع ملفات البايثون في المجلد"""
    python_files = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
    except Exception as e:
        logger.error(f"فشل البحث عن ملفات بايثون: {e}")
    return python_files

# ======= نظام تثبيت المتطلبات الحقيقي المُصلح تماماً ======= #
def find_pip_path(venv_path):
    """البحث عن مسار pip في البيئة الافتراضية بشكل آمن"""
    possible_paths = []
    
    if os.name != 'nt':  # Linux/Mac
        possible_paths = [
            os.path.join(venv_path, 'bin', 'pip'),
            os.path.join(venv_path, 'bin', 'pip3'),
            os.path.join(venv_path, 'bin', 'python') + ' -m pip',
            os.path.join(venv_path, 'bin', 'python3') + ' -m pip'
        ]
    else:  # Windows
        possible_paths = [
            os.path.join(venv_path, 'Scripts', 'pip.exe'),
            os.path.join(venv_path, 'Scripts', 'pip'),
            os.path.join(venv_path, 'Scripts', 'python.exe') + ' -m pip',
            os.path.join(venv_path, 'Scripts', 'python') + ' -m pip'
        ]
    
    for path in possible_paths:
        if ' -m pip' in path:
            # اختبار إذا كان python -m pip يعمل
            python_path = path.split(' -m pip')[0]
            if os.path.exists(python_path):
                try:
                    result = subprocess.run(
                        [python_path, '-m', 'pip', '--version'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        return path
                except:
                    continue
        else:
            if os.path.exists(path):
                return path
    
    return None

async def install_requirements_real_time(requirements_file, bot_lib_folder, user_id, chat_id, bot_name, bot_instance):
    """تثبيت المتطلبات حقيقياً مع عرض التقدم في الوقت الحقيقي - الإصدار المُصلح تماماً"""
    status_message = None
    try:
        # إرسال رسالة بدء التثبيت
        status_message = await bot_instance.send_message(
            chat_id, 
            f"📦 جاري تثبيت متطلبات البوت {bot_name}...\n⏳ قد تستغرق هذه العملية عدة دقائق"
        )
        
        if not os.path.exists(requirements_file):
            await status_message.edit_text("❌ ملف المتطلبات غير موجود")
            return False, "ملف المتطلبات غير موجود"

        # قراءة المتطلبات أولاً لعرضها
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                requirements_content = f.read().strip()
                requirements_list = [line for line in requirements_content.split('\n') if line.strip() and not line.startswith('#')]
            
            requirements_count = len(requirements_list)
            if requirements_count == 0:
                await status_message.edit_text("⚠️ ملف المتطلبات فارغ أو لا يحتوي على مكتبات صالحة")
                return False, "ملف المتطلبات فارغ"
                
        except Exception as e:
            await status_message.edit_text(f"⚠️ خطأ في قراءة ملف المتطلبات: {str(e)}")
            return False, f"خطأ في قراءة ملف المتطلبات: {str(e)}"

        # إنشاء البيئة الافتراضية إذا لم تكن موجودة
        venv_path = os.path.join(bot_lib_folder, 'venv')
        if not os.path.exists(venv_path):
            await status_message.edit_text("🔧 جاري إنشاء البيئة الافتراضية...")
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'venv', venv_path],
                    check=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=300
                )
                await status_message.edit_text("✅ تم إنشاء البيئة الافتراضية بنجاح")
            except subprocess.CalledProcessError as e:
                error_msg = f"❌ فشل إنشاء البيئة الافتراضية: {e.stderr}"
                await status_message.edit_text(error_msg)
                return False, error_msg
            except subprocess.TimeoutExpired:
                error_msg = "❌ انتهى وقت إنشاء البيئة الافتراضية"
                await status_message.edit_text(error_msg)
                return False, error_msg
            except Exception as e:
                error_msg = f"❌ خطأ غير متوقع في إنشاء البيئة: {str(e)}"
                await status_message.edit_text(error_msg)
                return False, error_msg

        # البحث عن مسار pip
        await status_message.edit_text("🔍 جاري البحث عن pip في البيئة الافتراضية...")
        pip_path = find_pip_path(venv_path)
        
        if not pip_path:
            await status_message.edit_text("❌ لم يتم العثور على pip في البيئة الافتراضية")
            return False, "لم يتم العثور على pip"

        # استخدام python -m pip إذا لم نجد pip مباشرة
        if ' -m pip' in pip_path:
            python_path = pip_path.split(' -m pip')[0]
            pip_command = [python_path, '-m', 'pip']
        else:
            pip_command = [pip_path]

        # تحديث pip أولاً
        await status_message.edit_text("🔄 جاري تحديث pip...")
        try:
            update_process = subprocess.run(
                pip_command + ['install', '--upgrade', 'pip'],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=bot_lib_folder
            )
            await status_message.edit_text("✅ تم تحديث pip بنجاح")
        except subprocess.TimeoutExpired:
            await status_message.edit_text("⚠️ انتهى وقت تحديث pip، المتابعة بالتثبيت...")
        except Exception as e:
            await status_message.edit_text("⚠️ فشل تحديث pip، المتابعة بالتثبيت...")

        # عرض قائمة المكتبات
        await status_message.edit_text(f"🚀 بدء تثبيت {requirements_count} مكتبة...\n\n📋 أول 10 مكتبات:\n" + "\n".join(requirements_list[:10]) + ("\n..." if len(requirements_list) > 10 else ""))

        # تثبيت المتطلبات
        await status_message.edit_text(f"🔧 جاري تثبيت {requirements_count} مكتبة...")

        try:
            # استخدام subprocess.run مع معالجة أفضل للأخطاء
            process = subprocess.run(
                pip_command + ['install', '-r', requirements_file],
                capture_output=True,
                text=True,
                timeout=600,  # 10 دقائق كحد أقصى
                cwd=bot_lib_folder
            )

            if process.returncode == 0:
                # تحليل المخرجات لاستخراج المكتبات المثبتة
                output_lines = process.stdout.split('\n')
                installed_packages = []
                
                for line in output_lines:
                    if 'Successfully installed' in line:
                        # استخراج أسماء المكتبات المثبتة
                        parts = line.split('Successfully installed')[-1].strip()
                        installed_packages.extend([pkg.strip() for pkg in parts.split() if pkg.strip()])
                
                success_message = f"✅ تم تثبيت متطلبات {bot_name} بنجاح!\n\n"
                if installed_packages:
                    success_message += f"📊 تم تثبيت {len(installed_packages)} مكتبة:\n"
                    success_message += ", ".join(installed_packages[:10])  # عرض أول 10 مكتبات فقط
                    if len(installed_packages) > 10:
                        success_message += f"\n... و {len(installed_packages) - 10} مكتبة أخرى"
                else:
                    success_message += "📦 تم تثبيت جميع المتطلبات بنجاح"
                
                success_message += "\n\n🎉 البوت جاهز للتشغيل!"
                
                await status_message.edit_text(success_message)
                return True, process.stdout
            else:
                # معالجة الأخطاء بشكل أفضل
                error_output = process.stderr if process.stderr else process.stdout
                error_lines = error_output.split('\n')
                
                # تصفية الأسطر المهمة فقط
                important_errors = []
                for line in error_lines:
                    if any(keyword in line.lower() for keyword in ['error', 'fail', 'not found', 'cannot', 'invalid']):
                        important_errors.append(line)
                
                if not important_errors:
                    important_errors = error_lines[-5:]  # آخر 5 أسطر إذا لم نجد أخطاء محددة
                
                error_message = f"❌ فشل تثبيت متطلبات {bot_name}:\n\n" + "\n".join(important_errors[-5:])
                await status_message.edit_text(error_message)
                return False, error_output

        except subprocess.TimeoutExpired:
            error_message = f"❌ انتهى وقت تثبيت متطلبات {bot_name} (10 دقائق)"
            await status_message.edit_text(error_message)
            return False, "انتهى الوقت المحدد"
        except Exception as e:
            error_message = f"❌ حدث خطأ غير متوقع أثناء التثبيت: {str(e)}"
            await status_message.edit_text(error_message)
            return False, str(e)

    except Exception as e:
        error_msg = f"❌ حدث خطأ غير متوقع: {str(e)}"
        try:
            if status_message:
                await status_message.edit_text(error_msg)
            else:
                await bot_instance.send_message(chat_id, error_msg)
        except:
            await bot_instance.send_message(chat_id, error_msg)
        return False, error_msg

async def install_requirements_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """معالجة تثبيت متطلبات البوت مع التقدم المرئي - الإصدار المُصلح تماماً"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in install_requirements_handler")
        return CHOOSE_ACTION

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in install_requirements_handler")
        return CHOOSE_ACTION

    user_id = query.from_user.id
    chat_id = query.message.chat_id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return CHOOSE_ACTION

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return CHOOSE_ACTION

    bot_info = user_bots[user_id]['bots'][actual_bot_name]
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')

    if not os.path.exists(requirements_file):
        await query.edit_message_text("❌ لا يوجد ملف requirements.txt لهذا البوت.")
        return CHOOSE_ACTION

    # بدء عملية التثبيت الحقيقية
    await query.edit_message_text(f"🚀 بدء عملية تثبيت المتطلبات للبوت {actual_bot_name}...")

    # استخدام asyncio.create_task للتشغيل غير المتزامن
    asyncio.create_task(
        run_installation_process(requirements_file, bot_info['lib_folder'], user_id, chat_id, actual_bot_name, context.bot, bot_info)
    )

    return CHOOSE_ACTION

async def run_installation_process(requirements_file, lib_folder, user_id, chat_id, bot_name, bot_instance, bot_info):
    """تشغيل عملية التثبيت في مهمة منفصلة"""
    try:
        success, message = await install_requirements_real_time(
            requirements_file, 
            lib_folder, 
            user_id, 
            chat_id, 
            bot_name, 
            bot_instance
        )
        
        # تحديث حالة البوت بعد التثبيت
        if success:
            bot_info['requirements_installed'] = True
            save_data()
            
    except Exception as e:
        logger.error(f"خطأ في عملية التثبيت: {e}")
        try:
            await bot_instance.send_message(chat_id, f"❌ فشل عملية التثبيت: {str(e)}")
        except:
            pass

# ======= دوال مساعدة للبوتات ======= #
async def check_bot_exists(user_id: int, bot_name: str) -> bool:
    """فحص إذا كان البوت موجود في قاعدة البيانات"""
    load_data()

    if user_id not in user_bots:
        return False

    if bot_name in user_bots[user_id]['bots']:
        return True

    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            return True

    return False

async def auto_start_all_bots(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    """تشغيل جميع البوتات تلقائياً للمستخدم"""
    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        return

    bot_count = 0
    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        if bot_info['status'] == 'stopped' and bot_info.get('auto_start', False):
            try:
                if start_bot_auto(user_id, bot_name, bot_info):
                    bot_count += 1
                    logger.info(f"تم التشغيل التلقائي للبوت: {bot_name}")
                else:
                    logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}")

            except Exception as e:
                logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}: {str(e)}")

    if bot_count > 0:
        await update.message.reply_text(f"✅ تم تشغيل {bot_count} بوت تلقائياً")

# ======= handlers المحادثة ======= #
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة أمر /start"""
    user_id = update.effective_user.id

    if user_id not in user_bots:
        user_bots[user_id] = {
            'bots': {},
            'settings': {
                'auto_restart': False,
                'restart_interval': 60,
                'max_restarts': 10,
                'env_vars': {},
                'notifications': True,
                'max_bots': 5,
                'max_ram_per_bot': 512,
                'max_cpu_per_bot': 50,
            }
        }
        save_data()

    user_sessions[user_id] = {
        'current_bot': None,
        'temp_files': []
    }

    keyboard = [
        [KeyboardButton("📤 رفع ملف/مشروع"), KeyboardButton("🤖 إدارة البوتات")],
        [KeyboardButton("⚙️ الإعدادات العامة"), KeyboardButton("📊 إحصائيات النظام")],
        [KeyboardButton("🛠️ إدارة المكتبات"), KeyboardButton("❌ إيقاف الجميع")],
        [KeyboardButton("🆘 المساعدة المتقدمة"), KeyboardButton("🌐 استيراد من GitHub")],
        [KeyboardButton("📦 إدارة الحزم")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        "🚀 مرحباً! أنا البوت المتقدم المتكامل لإدارة وتشغيل بوتات تيليجرام.\n\n"
        "📤 يمكنك رفع ملفات/مشاريع بايثون فردية أو مضغوطة\n"
        "🔄 نظام إعادة تشغيل تلقائي ذكي\n"
        "📦 دعم مكتبات خاصة لكل بوت\n"
        "⚙️ إعدادات متقدمة وأدوات مراقبة\n"
        "🌐 استيراد مباشر من GitHub\n\n"
        "اختر أحد الخيارات المتاحة:",
        reply_markup=reply_markup
    )

    # تشغيل البوتات التلقائي للمستخدم
    await auto_start_all_bots(update, context, user_id)

async def upload_option(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض خيارات الرفع"""
    keyboard = [
        [InlineKeyboardButton("📄 ملف بايثون فردي", callback_data="upload_python")],
        [InlineKeyboardButton("📦 ملف مضغوط (ZIP/TAR)", callback_data="upload_zip")],
        [InlineKeyboardButton("🔗 استيراد من GitHub", callback_data="import_github")],
        [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_upload")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "اختر طريقة رفع البوت:\n\n"
        "📄 ملف بايثون فردي - لرفع ملف .py مباشرة\n"
        "📦 ملف مضغوط - لرفع مشروع كامل مضغوط\n"
        "🔗 استيراد من GitHub - لاستيراد مشروع من GitHub\n\n"
        "اختر الخيار المناسب:",
        reply_markup=reply_markup
    )
    return UPLOAD

async def handle_upload_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة اختيار نوع الرفع"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_upload_choice")
        return UPLOAD

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_upload_choice")
        return UPLOAD

    user_id = query.from_user.id
    data = query.data

    if data == "upload_python":
        await query.edit_message_text("📤 يرجى رفع ملف بايثون (.py)")
        return UPLOAD
    elif data == "upload_zip":
        await query.edit_message_text("📦 يرجى رفع ملف مضغوط (ZIP/TAR) يحتوي على مشروع البوت")
        return ZIP_UPLOAD
    elif data == "import_github":
        await query.edit_message_text("🌐 أرسل رابط مستودع GitHub لاستيراد المشروع")
        return GITHUB_IMPORT
    elif data == "cancel_upload":
        await query.edit_message_text("❌ تم إلغاء عملية الرفع")
        return ConversationHandler.END

    return UPLOAD

async def handle_github_import(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة استيراد من GitHub"""
    user_id = update.effective_user.id
    github_url = update.message.text.strip()

    if github_url.startswith('github.com/'):
        github_url = 'https://' + github_url
    elif not github_url.startswith('https://github.com/'):
        await update.message.reply_text("❌ رابط GitHub غير صالح. يرجى إرسال رابط صحيح يبدأ بـ https://github.com/")
        return GITHUB_IMPORT

    temp_dir = os.path.join(TEMP_FOLDER, f"github_{user_id}_{int(time.time())}")
    os.makedirs(temp_dir, exist_ok=True)

    await update.message.reply_text("⏳ جاري استيراد المشروع من GitHub...")

    try:
        parts = github_url.split('/')
        if len(parts) < 5:
            raise ValueError("رابط GitHub غير صالح")

        owner = parts[3]
        repo = parts[4].replace('.git', '')

        zip_url = f"https://github.com/{owner}/{repo}/archive/main.zip"
        response = requests.get(zip_url, stream=True, timeout=30)

        if response.status_code != 200:
            zip_url = f"https://github.com/{owner}/{repo}/archive/master.zip"
            response = requests.get(zip_url, stream=True, timeout=30)

            if response.status_code != 200:
                raise ValueError("فشل في تنزيل المشروع من GitHub")

        zip_path = os.path.join(temp_dir, "project.zip")

        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        if not extract_archive(zip_path, temp_dir):
            raise ValueError("فشل في فك ضغط الملف")

        extracted_items = [item for item in os.listdir(temp_dir) if item != "project.zip"]
        if not extracted_items:
            raise ValueError("لم يتم العثور على ملفات بعد فك الضغط")

        extracted_dir = os.path.join(temp_dir, extracted_items[0])

        python_files = get_python_files(extracted_dir)

        if not python_files:
            await update.message.reply_text("❌ لم يتم العثور على أي ملفات بايثون في المشروع.")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return ConversationHandler.END

        if user_id not in user_sessions:
            user_sessions[user_id] = {}

        user_sessions[user_id]['temp_dir'] = temp_dir
        user_sessions[user_id]['python_files'] = python_files

        keyboard = []
        for i, file_path in enumerate(python_files):
            file_name = os.path.basename(file_path)
            rel_path = os.path.relpath(file_path, extracted_dir)
            keyboard.append([InlineKeyboardButton(f"{file_name} ({rel_path})", callback_data=f"select_file_{i}")])

        keyboard.append([InlineKeyboardButton("❌ إلغاء", callback_data="cancel_selection")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "✅ تم استيراد المشروع بنجاح. اختر الملف الرئيسي لتشغيله:",
            reply_markup=reply_markup
        )
        return FILE_SELECTION

    except Exception as e:
        error_msg = str(e)
        await update.message.reply_text(f"❌ حدث خطأ أثناء الاستيراد: {error_msg}")
        if 'temp_dir' in locals():
            shutil.rmtree(temp_dir, ignore_errors=True)
        return ConversationHandler.END

async def handle_zip_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة رفع الملفات المضغوطة"""
    user_id = update.effective_user.id

    if not update.message.document:
        await update.message.reply_text("❌ يرجى رفع ملف مضغوط صالح")
        return ZIP_UPLOAD

    document = update.message.document

    if not any(document.file_name.endswith(ext) for ext in ['.zip', '.tar', '.tar.gz', '.tgz']):
        await update.message.reply_text("❌ يرجى رفع ملف مضغوط (ZIP, TAR, TAR.GZ)")
        return ZIP_UPLOAD

    try:
        file = await context.bot.get_file(document.file_id)
        temp_dir = os.path.join(TEMP_FOLDER, f"zip_{user_id}_{int(time.time())}")
        os.makedirs(temp_dir, exist_ok=True)

        file_path = os.path.join(temp_dir, document.file_name)
        await file.download_to_drive(file_path)

        if protection_enabled and not is_admin(user_id):
            is_malicious, activity, threat_type = scan_zip_for_malicious_code(file_path, user_id)
            if is_malicious:
                if threat_type == "encrypted":
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه مشفر.")
                else:
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه يحتوي على ثغرات أمنية.")
                return ZIP_UPLOAD

        if not extract_archive(file_path, temp_dir):
            await update.message.reply_text("❌ فشل في فك ضغط الملف. قد يكون الملف تالفاً.")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return ZIP_UPLOAD

        python_files = get_python_files(temp_dir)

        if not python_files:
            await update.message.reply_text("❌ لم يتم العثور على أي ملفات بايثون في الأرشيف.")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return ConversationHandler.END

        if user_id not in user_sessions:
            user_sessions[user_id] = {}

        user_sessions[user_id]['temp_dir'] = temp_dir
        user_sessions[user_id]['python_files'] = python_files

        keyboard = []
        for i, file_path in enumerate(python_files):
            file_name = os.path.basename(file_path)
            rel_path = os.path.relpath(file_path, temp_dir)
            keyboard.append([InlineKeyboardButton(f"{file_name} ({rel_path})", callback_data=f"select_file_{i}")])

        keyboard.append([InlineKeyboardButton("❌ إلغاء", callback_data="cancel_selection")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "✅ تم فك الضغط بنجاح. اختر الملف الرئيسي لتشغيله:",
            reply_markup=reply_markup
        )
        return FILE_SELECTION

    except Exception as e:
        error_msg = str(e)
        await update.message.reply_text(f"❌ حدث خطأ أثناء معالجة الملف: {error_msg}")
        if 'temp_dir' in locals():
            shutil.rmtree(temp_dir, ignore_errors=True)
        return ZIP_UPLOAD

async def handle_file_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة اختيار الملف من القائمة"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_file_selection")
        return FILE_SELECTION

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_file_selection")
        return FILE_SELECTION

    user_id = query.from_user.id
    data = query.data

    if data == "cancel_selection":
        if user_id in user_sessions and 'temp_dir' in user_sessions[user_id]:
            shutil.rmtree(user_sessions[user_id]['temp_dir'], ignore_errors=True)
        await query.edit_message_text("❌ تم إلغاء الاختيار")
        return ConversationHandler.END

    if data.startswith("select_file_"):
        try:
            file_index = int(data.split('_')[2])
            selected_file = user_sessions[user_id]['python_files'][file_index]
            temp_dir = user_sessions[user_id]['temp_dir']

            base_name = os.path.basename(selected_file).replace('.py', '')
            bot_name = f"{base_name}_{int(time.time()) % 1000}"

            project_folder = os.path.join(UPLOAD_FOLDER, f"{user_id}_{bot_name}_project")
            os.makedirs(project_folder, exist_ok=True)

            shutil.copytree(temp_dir, project_folder, dirs_exist_ok=True)

            permanent_main_file = os.path.join(project_folder, os.path.basename(selected_file))

            requirements_path = None
            for root, _, files in os.walk(project_folder):
                for file in files:
                    if file.lower() == 'requirements.txt':
                        requirements_path = os.path.join(root, file)
                        break
                if requirements_path:
                    break

            bot_lib_folder = os.path.join(LIBRARY_FOLDER, f"{user_id}_{bot_name}")
            os.makedirs(bot_lib_folder, exist_ok=True)

            if user_id not in user_bots:
                user_bots[user_id] = {
                    'bots': {},
                    'settings': {
                        'auto_restart': False,
                        'restart_interval': 60,
                        'max_restarts': 10,
                        'env_vars': {},
                        'notifications': True,
                        'max_bots': 5,
                        'max_ram_per_bot': 512,
                        'max_cpu_per_bot': 50,
                    }
                }

            user_bots[user_id]['bots'][bot_name] = {
                'file_path': permanent_main_file,
                'project_path': project_folder,
                'status': 'stopped',
                'restarts': 0,
                'last_start': None,
                'log_file': os.path.join(LOG_FOLDER, f"{user_id}_{bot_name}.log"),
                'lib_folder': bot_lib_folder,
                'has_requirements': requirements_path is not None,
                'requirements_installed': False,
                'auto_start': True,
                'auto_restart': False,
                'restart_interval': 60,
                'max_restarts': 10,
                'env_vars': {}
            }

            if requirements_path:
                dest_requirements = os.path.join(bot_lib_folder, 'requirements.txt')
                shutil.copy2(requirements_path, dest_requirements)

            save_data()

            if 'temp_dir' in user_sessions[user_id]:
                shutil.rmtree(user_sessions[user_id]['temp_dir'], ignore_errors=True)

            keyboard = [
                [InlineKeyboardButton("▶️ تشغيل عادي", callback_data=f"run_normal_{bot_name}")],
                [InlineKeyboardButton("🔄 تشغيل مع إعادة تشغيل", callback_data=f"run_restart_{bot_name}")],
            ]

            if requirements_path:
                keyboard.append(
                    [InlineKeyboardButton("📦 تثبيت المتطلبات أولاً", callback_data=f"install_req_{bot_name}")])

            keyboard.extend([
                [InlineKeyboardButton("⚙️ تعديل الإعدادات", callback_data=f"settings_{bot_name}")],
                [InlineKeyboardButton("❌ حذف البوت", callback_data=f"delete_{bot_name}")]
            ])

            reply_markup = InlineKeyboardMarkup(keyboard)

            await query.edit_message_text(
                f"✅ تم اختيار الملف: {os.path.basename(selected_file)}\n\n"
                f"📝 اسم البوت: {bot_name}\n"
                f"📦 المشروع كامل: تم حفظه ✓\n"
                f"📦 المتطلبات: {'موجودة ✅' if requirements_path else 'غير موجودة ❌'}\n"
                f"💾 المسار: {project_folder}\n"
                f"🔄 التشغيل التلقائي: مفعل ✅\n\n"
                "اختر الإجراء المناسب:",
                reply_markup=reply_markup
            )
            return CHOOSE_ACTION

        except Exception as e:
            await query.edit_message_text(f"❌ حدث خطأ أثناء معالجة الملف: {str(e)}")
            if user_id in user_sessions and 'temp_dir' in user_sessions[user_id]:
                shutil.rmtree(user_sessions[user_id]['temp_dir'], ignore_errors=True)
            return ConversationHandler.END

    return FILE_SELECTION

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة رفع الملفات الفردية"""
    user_id = update.effective_user.id
    document = update.message.document

    if not document.file_name.endswith('.py'):
        await update.message.reply_text("❌ يرجى رفع ملف بايثون فقط (امتداد .py)")
        return UPLOAD

    try:
        file = await context.bot.get_file(document.file_id)
        base_name = document.file_name[:-3]
        bot_name = f"{base_name}_{int(time.time()) % 1000}"
        file_path = os.path.join(UPLOAD_FOLDER, f"{user_id}_{bot_name}.py")
        await file.download_to_drive(file_path)

        if protection_enabled and not is_admin(user_id):
            is_malicious, activity, threat_type = scan_file_for_malicious_code(file_path, user_id)
            if is_malicious:
                if threat_type == "encrypted":
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه مشفر.")
                else:
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه يحتوي على ثغرات أمنية.")
                return UPLOAD

        if user_id not in user_bots:
            user_bots[user_id] = {
                'bots': {},
                'settings': {
                    'auto_restart': False,
                    'restart_interval': 60,
                    'max_restarts': 10,
                    'env_vars': {},
                    'notifications': True,
                    'max_bots': 5,
                    'max_ram_per_bot': 512,
                    'max_cpu_per_bot': 50,
                }
            }

        bot_lib_folder = os.path.join(LIBRARY_FOLDER, f"{user_id}_{bot_name}")
        os.makedirs(bot_lib_folder, exist_ok=True)

        user_bots[user_id]['bots'][bot_name] = {
            'file_path': file_path,
            'status': 'stopped',
            'restarts': 0,
            'last_start': None,
            'log_file': os.path.join(LOG_FOLDER, f"{user_id}_{bot_name}.log"),
            'lib_folder': bot_lib_folder,
            'has_requirements': False,
            'requirements_installed': False,
            'auto_start': True,
            'auto_restart': False,
            'restart_interval': 60,
            'max_restarts': 10,
            'env_vars': {}
        }

        save_data()

        keyboard = [
            [InlineKeyboardButton("▶️ تشغيل عادي", callback_data=f"run_normal_{bot_name}")],
            [InlineKeyboardButton("🔄 تشغيل مع إعادة التشغيل", callback_data=f"run_restart_{bot_name}")],
            [InlineKeyboardButton("⚙️ تعديل الإعدادات", callback_data=f"settings_{bot_name}")],
            [InlineKeyboardButton("❌ حذف البوت", callback_data=f"delete_{bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            f"✅ تم رفع البوت: {bot_name}\n"
            f"🔄 التشغيل التلقائي: مفعل ✅\n\n"
            "اختر طريقة التشغيل:",
            reply_markup=reply_markup
        )
        return CHOOSE_ACTION

    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ أثناء رفع الملف: {str(e)}")
        return UPLOAD

async def run_bot_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str,
                          auto_restart: bool = False):
    """معالج تشغيل البوت"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in run_bot_handler")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in run_bot_handler")
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]
    file_path = bot_info['file_path']

    if not os.path.exists(file_path):
        await query.edit_message_text(f"❌ ملف البوت غير موجود: {file_path}")
        return

    process_key = f"{user_id}_{actual_bot_name}"
    if process_key in bot_processes and bot_processes[process_key].poll() is None:
        await query.edit_message_text(f"✅ البوت {actual_bot_name} يعمل بالفعل!")
        return

    try:
        env = os.environ.copy()
        if bot_info.get('requirements_installed', False):
            venv_path = os.path.join(bot_info['lib_folder'], 'venv')
            if os.path.exists(venv_path):
                if os.name != 'nt':
                    env['PATH'] = os.path.join(venv_path, 'bin') + os.pathsep + env['PATH']
                else:
                    env['PATH'] = os.path.join(venv_path, 'Scripts') + os.pathsep + env['PATH']

        for key, value in bot_info.get('env_vars', {}).items():
            env[key] = str(value)

        log_file = open(bot_info['log_file'], 'a', encoding='utf-8')
        process = subprocess.Popen(
            [sys.executable, file_path],
            stdout=log_file,
            stderr=log_file,
            text=True,
            env=env
        )

        bot_processes[process_key] = process
        bot_info['status'] = 'running'
        bot_info['last_start'] = datetime.now().isoformat()
        bot_info['pid'] = process.pid
        save_data()

        if auto_restart:
            if user_id not in restart_tasks:
                restart_tasks[user_id] = {}

            restart_tasks[user_id][actual_bot_name] = {
                'interval': bot_info.get('restart_interval', 60),
                'max_restarts': bot_info.get('max_restarts', 10),
                'restarts': 0
            }
            save_data()

            monitor_thread = threading.Thread(
                target=monitor_bot,
                args=(user_id, actual_bot_name, query.message.chat_id, context.bot),
                daemon=True
            )
            monitor_thread.start()

            await query.edit_message_text(
                f"✅ تم تشغيل البوت {actual_bot_name} مع تفعيل إعادة التشغيل التلقائي كل {bot_info.get('restart_interval', 60)} ثانية"
            )
        else:
            await query.edit_message_text(f"✅ تم تشغيل البوت {actual_bot_name} في وضع عادي")

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ أثناء تشغيل البوت: {str(e)}")
        logger.error(f"خطأ في تشغيل البوت: {e}")

async def stop_bot_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """إيقاف بوت"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in stop_bot_handler")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in stop_bot_handler")
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    if bot_info['status'] != 'running':
        await query.edit_message_text(f"✅ البوت {actual_bot_name} ليس قيد التشغيل!")
        return

    process_key = f"{user_id}_{actual_bot_name}"
    if process_key in bot_processes:
        try:
            process = bot_processes[process_key]
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            del bot_processes[process_key]
        except Exception as e:
            logger.error(f"خطأ في إيقاف البوت: {e}")

    if user_id in restart_tasks and actual_bot_name in restart_tasks[user_id]:
        del restart_tasks[user_id][actual_bot_name]
        if not restart_tasks[user_id]:
            del restart_tasks[user_id]

    bot_info['status'] = 'stopped'
    save_data()

    await query.edit_message_text(f"✅ تم إيقاف البوت {actual_bot_name} بنجاح")

async def delete_bot_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """حذف بوت والمشروع كامل"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in delete_bot_handler")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in delete_bot_handler")
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    if bot_info['status'] == 'running':
        process_key = f"{user_id}_{actual_bot_name}"
        if process_key in bot_processes:
            try:
                process = bot_processes[process_key]
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                del bot_processes[process_key]
            except Exception as e:
                logger.error(f"خطأ في إيقاف البوت للحذف: {e}")

    if user_id in restart_tasks and actual_bot_name in restart_tasks[user_id]:
        del restart_tasks[user_id][actual_bot_name]
        if not restart_tasks[user_id]:
            del restart_tasks[user_id]

    try:
        if os.path.exists(bot_info['file_path']):
            os.remove(bot_info['file_path'])

        if 'project_path' in bot_info and os.path.exists(bot_info['project_path']):
            shutil.rmtree(bot_info['project_path'])

        if os.path.exists(bot_info['log_file']):
            os.remove(bot_info['log_file'])
        if os.path.exists(bot_info['lib_folder']):
            shutil.rmtree(bot_info['lib_folder'])
    except Exception as e:
        logger.error(f"خطأ في حذف ملفات البوت: {e}")

    del user_bots[user_id]['bots'][actual_bot_name]
    save_data()

    await query.edit_message_text(f"✅ تم حذف البوت {actual_bot_name} وجميع ملفاته بنجاح")

def clean_log_content(text):
    """تنظيف المحتوى من الرموز الخاصة"""
    replacements = {
        '<': '⟨',
        '>': '⟩',
        '&': '＆',
        '^': '↑',
        '`': '´',
        '*': '∗',
        '_': '‗',
        '~': '∼',
    }

    for old_char, new_char in replacements.items():
        text = text.replace(old_char, new_char)

    return text

async def show_bot_logs(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض سجلات البوت"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in show_bot_logs")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in show_bot_logs")
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    if not os.path.exists(bot_info['log_file']):
        await query.edit_message_text("📝 لا توجد سجلات للبوت حتى الآن.")
        return

    try:
        with open(bot_info['log_file'], 'r', encoding='utf-8') as f:
            lines = f.readlines()
            last_lines = lines[-20:] if len(lines) > 20 else lines

        log_content = ''.join(last_lines).strip()

        if not log_content:
            await query.edit_message_text("📝 السجلات فارغة.")
            return

        if len(log_content) > 4000:
            log_content = log_content[-4000:]

        clean_log = clean_log_content(log_content)
        await query.edit_message_text(f"📋 آخر سجلات البوت {actual_bot_name}:\n\n{clean_log}")

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ أثناء قراءة السجلات: {str(e)}")

async def show_bot_settings(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض إعدادات البوت"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in show_bot_settings")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in show_bot_settings")
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    settings_text = f"""
⚙️ **إعدادات البوت: {actual_bot_name}**

📁 **المعلومات الأساسية:**
• المسار: `{bot_info['file_path']}`
• الحالة: {'🟢 يعمل' if bot_info['status'] == 'running' else '🔴 متوقف'}
• عدد إعادة التشغيل: {bot_info.get('restarts', 0)}
• آخر تشغيل: {bot_info.get('last_start', 'لم يبدأ بعد')}

📦 **المكتبات:**
• ملف المتطلبات: {'موجود ✅' if bot_info['has_requirements'] else 'غير موجود ❌'}
• المكتبات المثبتة: {'نعم ✅' if bot_info.get('requirements_installed', False) else 'لا ❌'}

🌐 **متغيرات البيئة:**
"""

    if bot_info.get('env_vars'):
        for key, value in bot_info.get('env_vars', {}).items():
            settings_text += f'• `{key}` = `{value}`\n'
    else:
        settings_text += '• لا توجد متغيرات\n'

    settings_text += f"""
🔄 **إعدادات التشغيل:**
• التشغيل التلقائي: {'✅' if bot_info.get('auto_start', False) else '❌'}
• إعادة التشغيل التلقائي: {'✅' if bot_info.get('auto_restart', False) else '❌'}
• فترة الإعادة: {bot_info.get('restart_interval', 60)} ثانية
• الحد الأقصى: {bot_info.get('max_restarts', 10)} مرة
"""

    keyboard = [
        [InlineKeyboardButton("🌐 إضافة/تعديل متغير", callback_data=f"add_env_{actual_bot_name}")],
        [InlineKeyboardButton("🗑️ حذف متغير", callback_data=f"delete_env_{actual_bot_name}")],
        [InlineKeyboardButton("🔄 تعديل إعدادات التشغيل", callback_data=f"edit_restart_{actual_bot_name}")],
        [InlineKeyboardButton("🔙 رجوع", callback_data=f"back_to_manage_{actual_bot_name}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(settings_text, reply_markup=reply_markup, parse_mode='HTML')

async def library_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إدارة مكتبات البوت"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return

    keyboard = []
    for bot_name in user_bots[user_id]['bots']:
        bot_info = user_bots[user_id]['bots'][bot_name]
        has_req = "📦" if bot_info.get('has_requirements', False) else "❌"
        installed = "✅" if bot_info.get('requirements_installed', False) else "❌"
        keyboard.append([InlineKeyboardButton(f"{has_req} {installed} {bot_name}", callback_data=f"lib_{bot_name}")])

    keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data="back_to_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "📚 إدارة مكتبات البوتات:\n\n"
        "📦 = يوجد ملف متطلبات\n"
        "✅ = تم تثبيت المتطلبات\n"
        "❌ = غير مثبت\n\n"
        "اختر البوت لإدارة مكتباته:",
        reply_markup=reply_markup
    )
    return LIBRARY_MANAGEMENT

async def show_library_options(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض خيارات المكتبات بشكل محسن"""
    query = update.callback_query

    if query is None:
        return

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')

    # التحقق من حالة المتطلبات
    has_requirements = os.path.exists(requirements_file)
    requirements_installed = bot_info.get('requirements_installed', False)
    
    # بناء النص التوضيحي
    status_text = f"📚 إدارة مكتبات البوت: {actual_bot_name}\n\n"
    status_text += f"📊 حالة المتطلبات:\n"
    status_text += f"   📁 ملف المتطلبات: {'موجود ✅' if has_requirements else 'غير موجود ❌'}\n"
    status_text += f"   🔧 التثبيت: {'مكتمل ✅' if requirements_installed else 'غير مثبت ❌'}\n"
    
    if has_requirements:
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                requirements_count = len([line for line in f.readlines() if line.strip() and not line.startswith('#')])
            status_text += f"   📦 عدد المكتبات: {requirements_count}\n"
        except:
            status_text += "   📦 عدد المكتبات: غير معروف\n"

    # بناء الأزرار
    keyboard = []
    
    if has_requirements:
        if requirements_installed:
            keyboard.append([InlineKeyboardButton("🔄 إعادة تثبيت المتطلبات", callback_data=f"install_req_{actual_bot_name}")])
            keyboard.append([InlineKeyboardButton("🗑️ إزالة التثبيت", callback_data=f"remove_req_{actual_bot_name}")])
        else:
            keyboard.append([InlineKeyboardButton("📦 تثبيت المتطلبات", callback_data=f"install_req_{actual_bot_name}")])
        
        keyboard.append([InlineKeyboardButton("📋 عرض المتطلبات", callback_data=f"view_req_{actual_bot_name}")])
    else:
        keyboard.append([InlineKeyboardButton("📝 إنشاء ملف متطلبات", callback_data=f"add_req_{actual_bot_name}")])
        keyboard.append([InlineKeyboardButton("📤 رفع ملف متطلبات", callback_data=f"upload_req_{actual_bot_name}")])

    keyboard.append([InlineKeyboardButton("🔙 رجوع إلى المكتبات", callback_data="back_to_libs")])

    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(status_text, reply_markup=reply_markup)

async def handle_library_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدارة المكتبات"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_library_management")
        return LIBRARY_MANAGEMENT

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_library_management")
        return LIBRARY_MANAGEMENT

    user_id = query.from_user.id
    data = query.data

    if data == "back_to_main":
        await query.edit_message_text("🏠 العودة إلى القائمة الرئيسية")
        return ConversationHandler.END

    if data == "back_to_libs":
        await library_management(update, context)
        return LIBRARY_MANAGEMENT

    if data.startswith("lib_"):
        bot_name = data[4:]
        await show_library_options(update, context, bot_name)

    elif data.startswith("install_req_"):
        bot_name = data[12:]
        await install_requirements_handler(update, context, bot_name)

    elif data.startswith("view_req_"):
        bot_name = data[9:]
        await view_requirements_detailed(update, context, bot_name)

    elif data.startswith("add_req_"):
        bot_name = data[8:]
        context.user_data['adding_req_to'] = bot_name
        await query.edit_message_text(
            "📝 أرسل محتوى ملف المتطلبات (كل سطر مكتبة واحدة):\n\n"
            "مثال:\n"
            "telegram\n"
            "python-telegram-bot\n"
            "requests==2.28.0\n"
            "python-dotenv"
        )
        return REQUIREMENTS_SETUP

    elif data.startswith("upload_req_"):
        bot_name = data[11:]
        context.user_data['uploading_req_to'] = bot_name
        await query.edit_message_text("📤 أرسل ملف requirements.txt:")
        return REQUIREMENTS_SETUP

    elif data.startswith("remove_req_"):
        bot_name = data[11:]
        await remove_requirements_handler(update, context, bot_name)

    return LIBRARY_MANAGEMENT

async def remove_requirements_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """حذف متطلبات البوت"""
    query = update.callback_query

    if query is None:
        return

    await query.answer()

    user_id = query.from_user.id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    # حذف البيئة الافتراضية
    venv_path = os.path.join(bot_info['lib_folder'], 'venv')
    if os.path.exists(venv_path):
        try:
            shutil.rmtree(venv_path)
        except Exception as e:
            logger.error(f"خطأ في حذف البيئة الافتراضية: {e}")

    bot_info['requirements_installed'] = False
    save_data()

    await query.edit_message_text(f"✅ تم حذف متطلبات البوت {actual_bot_name} وإزالة البيئة الافتراضية")

async def handle_requirements_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدخال المتطلبات"""
    user_id = update.effective_user.id
    message_text = update.message.text

    load_data()

    # التحقق من وجود البوت
    bot_name = context.user_data.get('adding_req_to') or context.user_data.get('uploading_req_to')
    if not bot_name or not await check_bot_exists(user_id, bot_name):
        await update.message.reply_text("❌ البوت غير موجود!")
        return ConversationHandler.END

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await update.message.reply_text("❌ البوت غير موجود!")
        return ConversationHandler.END

    bot_info = user_bots[user_id]['bots'][actual_bot_name]
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')

    try:
        # تحليل المتطلبات وحساب العدد
        lines = message_text.strip().split('\n')
        valid_requirements = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                valid_requirements.append(line)

        # حفظ المحتوى في ملف المتطلبات
        with open(requirements_file, 'w', encoding='utf-8') as f:
            f.write(message_text)

        bot_info['has_requirements'] = True
        save_data()

        # إعداد الأزرار
        keyboard = [
            [InlineKeyboardButton("🚀 تثبيت المتطلبات الآن", callback_data=f"install_req_{actual_bot_name}")],
            [InlineKeyboardButton("📋 عرض المتطلبات", callback_data=f"view_req_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"lib_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        success_message = f"""
✅ تم حفظ ملف المتطلبات للبوت {actual_bot_name} بنجاح!

📊 الإحصائيات:
• عدد الأسطر: {len(lines)}
• عدد المكتبات: {len(valid_requirements)}
• الحالة: جاهز للتثبيت

يمكنك الآن تثبيت المتطلبات أو تعديلها.
"""

        await update.message.reply_text(success_message, reply_markup=reply_markup)

    except Exception as e:
        error_message = f"❌ حدث خطأ أثناء حفظ الملف: {str(e)}"
        await update.message.reply_text(error_message)

    return ConversationHandler.END

async def show_bot_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض إدارة البوتات للمستخدم"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return ConversationHandler.END

    keyboard = []
    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        status = "🟢" if bot_info['status'] == 'running' else "🔴"
        keyboard.append([InlineKeyboardButton(f"{status} {bot_name}", callback_data=f"manage_{bot_name}")])

    keyboard.append([InlineKeyboardButton("➕ إضافة بوت جديد", callback_data="add_new_bot")])
    keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data="back_to_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "🤖 إدارة البوتات:\n\n"
        "🟢 = يعمل\n"
        "🔴 = متوقف\n\n"
        "اختر البوت للإدارة:",
        reply_markup=reply_markup
    )
    return BOT_MANAGEMENT

async def handle_bot_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدارة البوتات"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_bot_management")
        return BOT_MANAGEMENT

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_bot_management")
        return BOT_MANAGEMENT

    user_id = query.from_user.id
    data = query.data

    if data == "back_to_main":
        await query.edit_message_text("🏠 العودة إلى القائمة الرئيسية")
        return ConversationHandler.END

    if data == "add_new_bot":
        await query.edit_message_text("➡️ انتقل إلى خيار '📤 رفع ملف/مشروع' لإضافة بوت جديد")
        return ConversationHandler.END

    if data.startswith("manage_"):
        bot_name = data[7:]

        load_data()

        if not await check_bot_exists(user_id, bot_name):
            await query.edit_message_text("❌ البوت غير موجود!")
            return BOT_MANAGEMENT

        actual_bot_name = None
        for existing_bot in user_bots[user_id]['bots'].keys():
            if existing_bot.lower() == bot_name.lower():
                actual_bot_name = existing_bot
                break

        if not actual_bot_name:
            await query.edit_message_text("❌ البوت غير موجود!")
            return BOT_MANAGEMENT

        bot_info = user_bots[user_id]['bots'][actual_bot_name]
        status = "يعمل 🟢" if bot_info['status'] == 'running' else "متوقف 🔴"

        keyboard = [
            [InlineKeyboardButton("▶️ تشغيل", callback_data=f"start_{actual_bot_name}"),
             InlineKeyboardButton("⏹️ إيقاف", callback_data=f"stop_{actual_bot_name}")],
            [InlineKeyboardButton("📊 السجلات", callback_data=f"logs_{actual_bot_name}"),
             InlineKeyboardButton("⚙️ الإعدادات", callback_data=f"settings_{actual_bot_name}")],
            [InlineKeyboardButton("🗑️ حذف", callback_data=f"delete_{actual_bot_name}"),
             InlineKeyboardButton("📦 المكتبات", callback_data=f"lib_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="back_to_management")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"🤖 إدارة البوت: {actual_bot_name}\n"
            f"📊 الحالة: {status}\n"
            f"🔄 عدد عمليات إعادة التشغيل: {bot_info.get('restarts', 0)}\n"
            f"⏰ آخر تشغيل: {bot_info.get('last_start', 'لم يبدأ بعد')}\n\n"
            "اختر الإجراء المناسب:",
            reply_markup=reply_markup
        )
        return BOT_MANAGEMENT

    return BOT_MANAGEMENT

async def handle_button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة جميع الأزرار"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_button_callback")
        return

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_button_callback")
        return

    user_id = query.from_user.id
    data = query.data

    if data.startswith("run_normal_"):
        bot_name = data[11:]
        await run_bot_handler(update, context, bot_name, False)

    elif data.startswith("run_restart_"):
        bot_name = data[12:]
        await run_bot_handler(update, context, bot_name, True)

    elif data.startswith("stop_"):
        bot_name = data[5:]
        await stop_bot_handler(update, context, bot_name)

    elif data.startswith("delete_"):
        bot_name = data[7:]
        await delete_bot_handler(update, context, bot_name)

    elif data.startswith("logs_"):
        bot_name = data[5:]
        await show_bot_logs(update, context, bot_name)

    elif data.startswith("settings_"):
        bot_name = data[9:]
        await show_bot_settings(update, context, bot_name)

    elif data.startswith("install_req_"):
        bot_name = data[12:]
        await install_requirements_handler(update, context, bot_name)

    elif data.startswith("start_"):
        bot_name = data[6:]
        await run_bot_handler(update, context, bot_name, False)

    elif data.startswith("back_to_manage_"):
        bot_name = data[15:]
        await handle_bot_management(update, context)

    elif data == "back_to_management":
        await show_bot_management(update, context)

    elif data.startswith("add_env_"):
        bot_name = data[8:]
        context.user_data['editing_env'] = bot_name
        context.user_data['action'] = 'add'
        await query.edit_message_text(
            f"🌐 أرسل متغير البيئة للبوت {bot_name} بالصيغة:\n"
            "`اسم_المتغير=القيمة`\n\n"
            "مثال: `BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`"
        )
        return ENV_VAR_INPUT

    elif data.startswith("delete_env_"):
        bot_name = data[11:]
        context.user_data['editing_env'] = bot_name
        context.user_data['action'] = 'delete'

        load_data()
        if not await check_bot_exists(user_id, bot_name):
            await query.edit_message_text("❌ البوت غير موجود!")
            return

        actual_bot_name = None
        for existing_bot in user_bots[user_id]['bots'].keys():
            if existing_bot.lower() == bot_name.lower():
                actual_bot_name = existing_bot
                break

        if not actual_bot_name:
            await query.edit_message_text("❌ البوت غير موجود!")
            return

        bot_info = user_bots[user_id]['bots'][actual_bot_name]
        env_vars = bot_info.get('env_vars', {})

        if not env_vars:
            await query.edit_message_text("❌ لا توجد متغيرات بيئة لحذفها")
            return

        keyboard = []
        for key in env_vars.keys():
            keyboard.append([InlineKeyboardButton(f"🗑️ {key}", callback_data=f"del_env_{key}_{actual_bot_name}")])

        keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data=f"settings_{actual_bot_name}")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text("اختر المتغير لحذفه:", reply_markup=reply_markup)

    elif data.startswith("del_env_"):
        parts = data.split('_')
        if len(parts) >= 4:
            key = parts[2]
            bot_name = '_'.join(parts[3:])

            load_data()
            if not await check_bot_exists(user_id, bot_name):
                await query.edit_message_text("❌ البوت غير موجود!")
                return

            actual_bot_name = None
            for existing_bot in user_bots[user_id]['bots'].keys():
                if existing_bot.lower() == bot_name.lower():
                    actual_bot_name = existing_bot
                    break

            if not actual_bot_name:
                await query.edit_message_text("❌ البوت غير موجود!")
                return

            bot_info = user_bots[user_id]['bots'][actual_bot_name]
            if key in bot_info.get('env_vars', {}):
                del bot_info['env_vars'][key]
                save_data()
                await query.edit_message_text(f"✅ تم حذف المتغير: {key}")
                await show_bot_settings(update, context, actual_bot_name)
            else:
                await query.edit_message_text("❌ المتغير غير موجود!")

    elif data.startswith("edit_restart_"):
        bot_name = data[13:]
        context.user_data['editing_env'] = bot_name
        context.user_data['action'] = 'restart_settings'

        load_data()
        if not await check_bot_exists(user_id, bot_name):
            await query.edit_message_text("❌ البوت غير موجود!")
            return

        actual_bot_name = None
        for existing_bot in user_bots[user_id]['bots'].keys():
            if existing_bot.lower() == bot_name.lower():
                actual_bot_name = existing_bot
                break

        if not actual_bot_name:
            await query.edit_message_text("❌ البوت غير موجود!")
            return

        bot_info = user_bots[user_id]['bots'][actual_bot_name]

        await query.edit_message_text(
            f"⚙️ إعدادات إعادة التشغيل للبوت {actual_bot_name}:\n\n"
            f"• التشغيل التلقائي: {'✅' if bot_info.get('auto_start', False) else '❌'}\n"
            f"• إعادة التشغيل التلقائي: {'✅' if bot_info.get('auto_restart', False) else '❌'}\n"
            f"• فترة إعادة التشغيل: {bot_info.get('restart_interval', 60)} ثانية\n"
            f"• الحد الأقصى: {bot_info.get('max_restarts', 10)} مرة\n\n"
            "📝 أرسل الإعدادات الجديدة بالصيغة:\n"
            "`تشغيل_تلقائي إعادة_تشغيل فترة_ثانية حد_أقصى`\n\n"
            "مثال: `نعم نعم 60 10`"
        )
        return ENV_VAR_INPUT

    elif data.startswith("lib_"):
        bot_name = data[4:]
        context.user_data['current_bot'] = bot_name
        await handle_library_management(update, context)

async def handle_env_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدخال متغيرات البيئة"""
    user_id = update.effective_user.id
    text = update.message.text.strip()

    if 'editing_env' not in context.user_data:
        await update.message.reply_text("❌ لا توجد عملية تحرير نشطة")
        return

    bot_name = context.user_data['editing_env']
    action = context.user_data.get('action')

    load_data()
    if not await check_bot_exists(user_id, bot_name):
        await update.message.reply_text("❌ البوت غير موجود!")
        return

    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await update.message.reply_text("❌ البوت غير موجود!")
        return

    bot_info = user_bots[user_id]['bots'][actual_bot_name]

    try:
        if action == 'add':
            if '=' in text:
                key, value = text.split('=', 1)
                key = key.strip()
                value = value.strip()

                if 'env_vars' not in bot_info:
                    bot_info['env_vars'] = {}

                bot_info['env_vars'][key] = value
                save_data()

                await update.message.reply_text(f"✅ تم إضافة المتغير: `{key}` = `{value}`", parse_mode='HTML')
                await show_bot_settings(update, context, actual_bot_name)
            else:
                await update.message.reply_text("❌ صيغة غير صحيحة! استخدم: اسم_المتغير=القيمة")

        elif action == 'restart_settings':
            parts = text.split()
            if len(parts) == 4:
                auto_start = parts[0].lower() in ['نعم', 'yes', 'true', '1', 'y', 'true', 'on']
                auto_restart = parts[1].lower() in ['نعم', 'yes', 'true', '1', 'y', 'true', 'on']

                try:
                    interval = int(parts[2])
                    max_restarts = int(parts[3])
                except ValueError:
                    await update.message.reply_text("❌ يجب أن تكون الفترة والحد أرقاماً صحيحة")
                    return

                bot_info['auto_start'] = auto_start
                bot_info['auto_restart'] = auto_restart
                bot_info['restart_interval'] = max(30, interval)
                bot_info['max_restarts'] = max(1, max_restarts)

                save_data()

                await update.message.reply_text(
                    f"✅ تم تحديث إعدادات إعادة التشغيل:\n"
                    f"• التشغيل التلقائي: {'✅' if auto_start else '❌'}\n"
                    f"• إعادة التشغيل التلقائي: {'✅' if auto_restart else '❌'}\n"
                    f"• الفترة: {bot_info['restart_interval']} ثانية\n"
                    f"• الحد الأقصى: {bot_info['max_restarts']} مرة"
                )
                await show_bot_settings(update, context, actual_bot_name)
            else:
                await update.message.reply_text("❌ صيغة غير صحيحة! استخدم: نعم نعم 60 10")

    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ: {str(e)}")

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إلغاء المحادثة والعودة إلى القائمة الرئيسية"""
    user_id = update.effective_user.id

    if user_id in user_sessions:
        if 'temp_dir' in user_sessions[user_id]:
            shutil.rmtree(user_sessions[user_id]['temp_dir'], ignore_errors=True)
        user_sessions[user_id] = {'current_bot': None, 'temp_files': []}

    keyboard = [
        [KeyboardButton("📤 رفع ملف/مشروع"), KeyboardButton("🤖 إدارة البوتات")],
        [KeyboardButton("⚙️ الإعدادات العامة"), KeyboardButton("📊 إحصائيات النظام")],
        [KeyboardButton("🛠️ إدارة المكتبات"), KeyboardButton("❌ إيقاف الجميع")],
        [KeyboardButton("🆘 المساعدة المتقدمة"), KeyboardButton("🌐 استيراد من GitHub")],
        [KeyboardButton("📦 إدارة الحزم")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        "✅ تم إلغاء العملية الحالية.\n\n"
        "اختر أحد الخيارات المتاحة:",
        reply_markup=reply_markup
    )
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض رسالة المساعدة"""
    help_text = """
🆘 **المساعدة المتقدمة - بوت إدارة البوتات**

📋 **الأوامر المتاحة:**

📤 **رفع ملف/مشروع** - رفع بوتات بايثون فردية أو مشاريع مضغوطة
🤖 **إدارة البوتات** - عرض وإدارة جميع البوتات الخاصة بك
⚙️ **الإعدادات العامة** - ضبط إعدادات النظام العامة
📊 **إحصائيات النظام** - عرض إحصائيات أداء النظام
🛠️ **إدارة المكتبات** - إدارة مكتبات ومتطلبات البوتات
❌ **إيقاف الجميع** - إوقف جميع البوتات النشطة
🌐 **استيراد من GitHub** - استيراد مشاريع مباشرة من GitHub
📦 **إدارة الحزم** - إدارة حزم ومكتبات النظام

🔧 **ميزات متقدمة:**
- تشغيل متعدد للبوتات
- إعادة تشغيل تلقائي
- بيئات افتراضية منعزلة
- إدارة المتطلبات التلقائية
- مراقبة الأداء
- سجلات مفصلة
- نظام حماية متقدم ضد الملفات الضارة

💡 **نصائح:**
- تأكد من وجود ملف `requirements.txt` للمشاريع الكبيرة
- استخدم البيئات الافتراضية لعزل المكتبات
- راقب استخدام الذاكرة والمسؤولية
- احفظ نسخ احتياطية من الإعدادات المهمة
- تفعيل الحماية لمنع رفع الملفات الضارة

📞 **للدعم الفني:**
@taha_khoja
    """

    await update.message.reply_text(help_text, parse_mode='HTML')

async def stop_all_bots(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إيقاف جميع البوتات النشطة"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات نشطة حتى الآن.")
        return

    stopped_count = 0
    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        if bot_info['status'] == 'running':
            process_key = f"{user_id}_{bot_name}"
            if process_key in bot_processes:
                try:
                    process = bot_processes[process_key]
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    del bot_processes[process_key]
                    stopped_count += 1
                except Exception as e:
                    logger.error(f"خطأ في إيقاف البوت {bot_name}: {e}")

            bot_info['status'] = 'stopped'

    if user_id in restart_tasks:
        del restart_tasks[user_id]

    save_data()

    await update.message.reply_text(f"✅ تم إيقاف {stopped_count} بوت بنجاح.")

async def show_statistics(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض إحصائيات النظام"""
    user_id = update.effective_user.id

    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    total_bots = 0
    running_bots = 0
    total_restarts = 0

    load_data()
    if user_id in user_bots:
        total_bots = len(user_bots[user_id]['bots'])
        for bot_name, bot_info in user_bots[user_id]['bots'].items():
            if bot_info['status'] == 'running':
                running_bots += 1
            total_restarts += bot_info.get('restarts', 0)

    stats_text = f"""
📊 **إحصائيات النظام**

🖥️ **أداء النظام:**
• استخدام المعالج: {cpu_percent}%
• استخدام الذاكرة: {memory.percent}% ({memory.used // 1024 // 1024}MB / {memory.total // 1024 // 1024}MB)
• استخدام التخزين: {disk.percent}% ({disk.used // 1024 // 1024 // 1024}GB / {disk.total // 1024 // 1024 // 1024}GB)

🤖 **إحصائيات البوتات:**
• إجمالي البوتات: {total_bots}
• البوتات النشطة: {running_bots}
• البوتات المتوقفة: {total_bots - running_bots}
• إجمالي عمليات إعادة التشغيل: {total_restarts}

📈 **معلومات إضافية:**
• وقت التشغيل: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• عدد المستخدمين: {len(user_bots)}
• المهام النشطة: {len(restart_tasks.get(user_id, {}))}
• نظام الحماية: {'مفعل ✅' if protection_enabled else 'معطل ❌'}
• مستوى الحماية: {protection_level}
    """

    await update.message.reply_text(stats_text, parse_mode='HTML')

async def show_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض الإعدادات العامة"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots:
        user_bots[user_id] = {
            'bots': {},
            'settings': {
                'auto_restart': False,
                'restart_interval': 60,
                'max_restarts': 10,
                'env_vars': {},
                'notifications': True,
                'max_bots': 5,
                'max_ram_per_bot': 512,
                'max_cpu_per_bot': 50,
            }
        }
        save_data()

    settings = user_bots[user_id]['settings']

    settings_text = f"""
⚙️ **الإعدادات العامة**

🔄 **إعادة التشغيل التلقائي:**
• تفعيل إعادة التشغيل: {'✅' if settings['auto_restart'] else '❌'}
• الفترة الزمنية: {settings['restart_interval']} ثانية
• الحد الأقصى لإعادة التشغيل: {settings['max_restarts']} مرة

🔔 **الإشعارات:**
• الإشعارات: {'✅' if settings['notifications'] else '❌'}

📊 **الحدود:**
• الحد الأقصى للبوتات: {settings['max_bots']}
• الحد الأقصى للذاكرة لكل بوت: {settings['max_ram_per_bot']} MB
• الحد الأقصى للمعالجة لكل بوت: {settings['max_cpu_per_bot']}%

🌐 **متغيرات البيئة العامة:**
"""
    if settings['env_vars']:
        for key, value in settings['env_vars'].items():
            settings_text += f'• {key}={value}\n'
    else:
        settings_text += '• لا توجد متغيرات\n'

    keyboard = [
        [InlineKeyboardButton("🔄 تعديل إعدادات إعادة التشغيل", callback_data="edit_restart_settings")],
        [InlineKeyboardButton("🔔 تعديل الإشعارات", callback_data="edit_notifications")],
        [InlineKeyboardButton("📊 تعديل الحدود", callback_data="edit_limits")],
        [InlineKeyboardButton("🌐 إدارة متغيرات البيئة", callback_data="edit_env_vars")],
        [InlineKeyboardButton("🔙 رجوع", callback_data="back_to_main")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(settings_text, reply_markup=reply_markup, parse_mode='HTML')
    return BOT_CONFIG

async def handle_settings_edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة تعديل الإعدادات"""
    query = update.callback_query

    if query is None:
        logger.error("Query is None in handle_settings_edit")
        return ConversationHandler.END

    await query.answer()

    if query.message is None:
        logger.error("Query message is None in handle_settings_edit")
        return ConversationHandler.END

    user_id = query.from_user.id
    data = query.data

    load_data()

    if user_id not in user_bots:
        await query.edit_message_text("❌ لم يتم العثور على إعدادات المستخدم!")
        return ConversationHandler.END

    settings = user_bots[user_id]['settings']

    if data == "back_to_main":
        await query.edit_message_text("🏠 العودة إلى القائمة الرئيسية")
        return ConversationHandler.END

    elif data == "edit_restart_settings":
        await query.edit_message_text(
            "🔄 إعدادات إعادة التشغيل التلقائي:\n\n"
            f"الحالة الحالية: {'مفعل' if settings['auto_restart'] else 'معطل'}\n"
            f"الفترة الزمنية: {settings['restart_interval']} ثانية\n"
            f"الحد الأقصى: {settings['max_restarts']} مرة\n\n"
            "📝 أرسل الإعدادات الجديدة بالصيغة:\n"
            "`تفعيل/تعطيل فترة_ثواني حد_أقصى`\n\n"
            "مثال: `تفعيل 60 10`"
        )
        context.user_data['editing'] = 'restart'
        return SETTINGS_INPUT

    elif data == "edit_notifications":
        new_status = not settings['notifications']
        settings['notifications'] = new_status
        save_data()

        await query.edit_message_text(f"✅ تم {'تفعيل' if new_status else 'تعطيل'} الإشعارات")
        return await show_settings(update, context)

    elif data == "edit_limits":
        await query.edit_message_text(
            "📊 تعديل الحدود:\n\n"
            f"الحد الأقصى للبوتات: {settings['max_bots']}\n"
            f"الحد الأقصى للذاكرة: {settings['max_ram_per_bot']} MB\n"
            f"الحد الأقصى للمعالجة: {settings['max_cpu_per_bot']}%\n\n"
            "📝 أرسل الحدود الجديدة بالصيغة:\n"
            "`عدد_البوتات ذاكرة_MB معالجة_%`\n\n"
            "مثال: `5 512 50`"
        )
        context.user_data['editing'] = 'limits'
        return SETTINGS_INPUT

    elif data == "edit_env_vars":
        await query.edit_message_text(
            "🌐 إدارة متغيرات البيئة:\n\n"
            "المتغيرات الحالية:\n"
        )

        if settings['env_vars']:
            env_text = ""
            for key, value in settings['env_vars'].items():
                env_text += f"• {key}={value}\n"
            await query.edit_message_text(
                env_text + "\nأرسل متغير جديد بالصيغة: `المفتاح=القيمة`\nأو أرسل `حذف المفتاح` للحذف")
        else:
            await query.edit_message_text("• لا توجد متغيرات\n\nأرسل متغير جديد بالصيغة: `المفتاح=القيمة`")

        context.user_data['editing'] = 'env_vars'
        return SETTINGS_INPUT

    return BOT_CONFIG

async def handle_settings_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدخال الإعدادات"""
    user_id = update.effective_user.id
    text = update.message.text.strip()
    editing_type = context.user_data.get('editing')

    load_data()

    if user_id not in user_bots:
        await update.message.reply_text("❌ لم يتم العثور على إعدادات المستخدم!")
        return ConversationHandler.END

    settings = user_bots[user_id]['settings']

    try:
        if editing_type == 'restart':
            parts = text.split()
            if len(parts) == 3:
                status = parts[0].lower()
                interval = int(parts[1])
                max_restarts = int(parts[2])

                settings['auto_restart'] = status in ['تفعيل', 'true', 'نعم', 'yes', '1', 'on']
                settings['restart_interval'] = max(30, interval)
                settings['max_restarts'] = max(1, max_restarts)

                save_data()
                await update.message.reply_text(
                    f"✅ تم تحديث إعدادات إعادة التشغيل:\n"
                    f"• الحالة: {'مفعل' if settings['auto_restart'] else 'معطل'}\n"
                    f"• الفترة: {settings['restart_interval']} ثانية\n"
                    f"• الحد الأقصى: {settings['max_restarts']} مرة"
                )

        elif editing_type == 'limits':
            parts = text.split()
            if len(parts) == 3:
                max_bots = int(parts[0])
                max_ram = int(parts[1])
                max_cpu = int(parts[2])

                settings['max_bots'] = max(1, max_bots)
                settings['max_ram_per_bot'] = max(64, max_ram)
                settings['max_cpu_per_bot'] = max(10, min(100, max_cpu))

                save_data()
                await update.message.reply_text(
                    f"✅ تم تحديث الحدود:\n"
                    f"• الحد الأقصى للبوتات: {settings['max_bots']}\n"
                    f"• الحد الأقصى للذاكرة: {settings['max_ram_per_bot']} MB\n"
                    f"• الحد الأقصى للمعالجة: {settings['max_cpu_per_bot']}%"
                )

        elif editing_type == 'env_vars':
            if text.startswith('حذف '):
                key = text[4:].strip()
                if key in settings['env_vars']:
                    del settings['env_vars'][key]
                    save_data()
                    await update.message.reply_text(f"✅ تم حذف المتغير: {key}")
                else:
                    await update.message.reply_text("❌ المتغير غير موجود!")
            elif '=' in text:
                key, value = text.split('=', 1)
                key = key.strip()
                value = value.strip()

                settings['env_vars'][key] = value
                save_data()
                await update.message.reply_text(f"✅ تم إضافة/تعديل المتغير: {key}={value}")
            else:
                await update.message.reply_text("❌ صيغة غير صحيحة! استخدم: المفتاح=القيمة")

    except (ValueError, IndexError):
        await update.message.reply_text("❌ صيغة غير صحيحة! يرجى إدخال البيانات بالشكل الصحيح.")

    return await show_settings(update, context)

async def debug_bots(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """دالة تصحيح للأخطاء - لعرض حالة البوتات"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ لا توجد بوتات في قاعدة البيانات")
        return

    debug_text = "🔍 **حالة البوتات:**\n\n"
    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        debug_text += f"🤖 **{bot_name}:**\n"
        debug_text += f"   📁 المسار: `{bot_info.get('file_path', 'غير محدد')}`\n"
        debug_text += f"   🚦 الحالة: {bot_info.get('status', 'غير معروف')}\n"
        debug_text += f"   📦 متطلبات: {bot_info.get('has_requirements', False)}\n"
        debug_text += f"   🔧 مثبت: {bot_info.get('requirements_installed', False)}\n"
        debug_text += f"   🔄 تشغيل تلقائي: {bot_info.get('auto_start', False)}\n"
        debug_text += f"   🔁 إعادة تشغيل: {bot_info.get('auto_restart', False)}\n\n"

    await update.message.reply_text(debug_text, parse_mode='HTML')

async def list_bots(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض قائمة البوتات"""
    user_id = update.effective_user.id
    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return

    bot_list = "📋 **البوتات الخاصة بك:**\n\n"
    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        status = "🟢 يعمل" if bot_info['status'] == 'running' else "🔴 متوقف"
        bot_list += f"🤖 **{bot_name}** - {status}\n"
        bot_list += f"   📁 `{bot_info['file_path']}`\n"
        bot_list += f"   🔄 إعادة تشغيل: {bot_info.get('restarts', 0)} مرة\n\n"

    await update.message.reply_text(bot_list, parse_mode='HTML')

async def start_all_bots_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """تشغيل جميع البوتات التلقائي"""
    user_id = update.effective_user.id

    await update.message.reply_text("🔄 جاري تشغيل جميع البوتات التلقائي...")

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return

    started_count = 0
    total_bots = len(user_bots[user_id]['bots'])

    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        if bot_info['status'] == 'stopped':
            try:
                if start_bot_auto(user_id, bot_name, bot_info):
                    started_count += 1
                    logger.info(f"تم التشغيل التلقائي للبوت: {bot_name}")
                else:
                    logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}")
            except Exception as e:
                logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}: {str(e)}")

    await update.message.reply_text(f"✅ تم تشغيل {started_count} من أصل {total_bots} بوت تلقائياً")

async def fix_bot_states_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إصلاح حالات البوتات غير المتزامنة"""
    user_id = update.effective_user.id

    await update.message.reply_text("🔧 جاري إصلاح حالات البوتات...")

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return

    fixed_count = 0
    total_bots = len(user_bots[user_id]['bots'])

    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        pid = bot_info.get('pid')
        status = bot_info.get('status', 'stopped')

        # التحقق مما إذا كانت العملية لا تزال تعمل
        process_running = check_process_running(pid)

        if status == 'running' and not process_running:
            logger.warning(f"إصلاح حالة البوت {bot_name}: مسجل كقيد التشغيل ولكن العملية غير نشطة")
            bot_info['status'] = 'stopped'
            fixed_count += 1
        elif status == 'stopped' and process_running:
            logger.warning(f"إصلاح حالة البوت {bot_name}: مسجل كمتوقف ولكن العملية نشطة")
            bot_info['status'] = 'running'
            fixed_count += 1

    if fixed_count > 0:
        save_data()
        await update.message.reply_text(f"✅ تم إصلاح {fixed_count} من أصل {total_bots} بوت")
    else:
        await update.message.reply_text("✅ جميع حالات البوتات صحيحة، لا حاجة للإصلاح")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالج الأخطاء العام"""
    logger.error(f"حدث خطأ: {context.error}")

    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ حدث خطأ غير متوقع. يرجى المحاولة مرة أخرى."
            )
    except Exception as e:
        logger.error(f"فشل في إرسال رسالة الخطأ: {e}")

def main():
    """الدالة الرئيسية"""
    if not BOT_TOKEN or BOT_TOKEN == '7':
        logger.error("❌ يرجى تعيين توكن البوت الصحيح في المتغير BOT_TOKEN")
        return

    try:
        application = Application.builder().token(BOT_TOKEN).build()

        conv_handler = ConversationHandler(
            entry_points=[
                MessageHandler(filters.Regex("^(📤 رفع ملف/مشروع)$"), upload_option),
                MessageHandler(filters.Regex("^(🤖 إدارة البوتات)$"), show_bot_management),
                MessageHandler(filters.Regex("^(🛠️ إدارة المكتبات)$"), library_management),
                MessageHandler(filters.Regex("^(⚙️ الإعدادات العامة)$"), show_settings),
                MessageHandler(filters.Regex("^(🌐 استيراد من GitHub)$"), upload_option),
            ],
            states={
                UPLOAD: [
                    CallbackQueryHandler(handle_upload_choice,
                                         pattern="^(upload_python|upload_zip|import_github|cancel_upload)$"),
                    MessageHandler(filters.Document.ALL, handle_document),
                ],
                GITHUB_IMPORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_github_import)],
                ZIP_UPLOAD: [MessageHandler(filters.Document.ALL, handle_zip_upload)],
                FILE_SELECTION: [
                    CallbackQueryHandler(handle_file_selection, pattern="^(select_file_|cancel_selection)")],
                CHOOSE_ACTION: [
                    CallbackQueryHandler(handle_button_callback, pattern="^(run_|install_|settings_|delete_|cancel_)")],
                BOT_MANAGEMENT: [
                    CallbackQueryHandler(handle_bot_management, pattern="^(manage_|add_new_bot|back_to_)")],
                LIBRARY_MANAGEMENT: [CallbackQueryHandler(handle_library_management,
                                                          pattern="^(lib_|reinstall_|remove_|install_|add_|upload_|view_|back_to_)")],
                BOT_CONFIG: [CallbackQueryHandler(handle_settings_edit, pattern="^(edit_|view_|back_to_)")],
                ENV_VAR_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_env_input)],
                SETTINGS_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_settings_input)],
                REQUIREMENTS_SETUP: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, handle_requirements_input),
                    MessageHandler(filters.Document.ALL, handle_requirements_upload)
                ],
            },
            fallbacks=[CommandHandler('cancel', cancel), MessageHandler(filters.Regex("^/cancel$"), cancel)],
            allow_reentry=True,
            per_message=False
        )

        application.add_handler(conv_handler)
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("stop_all", stop_all_bots))
        application.add_handler(CommandHandler("debug", debug_bots))
        application.add_handler(CommandHandler("list", list_bots))
        application.add_handler(CommandHandler("start_all", start_all_bots_command))
        application.add_handler(CommandHandler("fix_states", fix_bot_states_command))
        application.add_handler(MessageHandler(filters.Regex("^(❌ إيقاف الجميع)$"), stop_all_bots))
        application.add_handler(MessageHandler(filters.Regex("^(📊 إحصائيات النظام)$"), show_statistics))
        application.add_handler(MessageHandler(filters.Regex("^(🆘 المساعدة المتقدمة)$"), help_command))
        application.add_handler(CallbackQueryHandler(handle_button_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_env_input))

        # إضافة معالج الأخطاء
        application.add_error_handler(error_handler)

        logger.info("🤖 بدء تشغيل بوت إدارة البوتات...")
        print("🤖 البوت يعمل الآن! استخدم /start للبدء")

        # تشغيل البوتات التلقائي عند بدء التشغيل
        logger.info("جاري تشغيل البوتات التلقائية...")
        auto_start_all_bots_on_load()

        application.run_polling(drop_pending_updates=True)

    except Exception as e:
        logger.error(f"❌ فشل تشغيل البوت: {e}")
        print(f"❌ فشل تشغيل البوت: {e}")

if __name__ == '__main__':
    main()
