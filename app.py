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
import html
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

                # التحقق من إعداد التشغيل التلقائي
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

        # إضافة متغيرات البيئة المخصصة
        for key, value in bot_info.get('env_vars', {}).items():
            env[key] = str(value)

        # فتح ملف السجل
        log_file = open(bot_info['log_file'], 'a', encoding='utf-8')

        # تشغيل البوت
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
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue

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
                logger.info(f"توقف إعادة تشغيل البوت {bot_name} بعد {max_restarts} محاولات")

                if user_id in restart_tasks and bot_name in restart_tasks[user_id]:
                    del restart_tasks[user_id][bot_name]
                    if not restart_tasks[user_id]:
                        del restart_tasks[user_id]

                save_data()
                break

        time.sleep(2)

# تحميل البيانات عند الاستيراد
load_data()

def extract_archive(file_path, extract_to):
    """فك ضغط الملفات المضغوطة بشكل كامل"""
    try:
        # التأكد من وجود مجلد الاستخراج
        os.makedirs(extract_to, exist_ok=True)
        
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # استخراج جميع الملفات
                zip_ref.extractall(extract_to)
                # الحصول على قائمة الملفات المستخرجة
                extracted_files = zip_ref.namelist()
                logger.info(f"تم استخراج {len(extracted_files)} ملف من الأرشيف ZIP")
                return True, extracted_files
                
        elif file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)
                extracted_files = tar_ref.getnames()
                logger.info(f"تم استخراج {len(extracted_files)} ملف من الأرشيف TAR.GZ")
                return True, extracted_files
                
        elif file_path.endswith('.tar'):
            with tarfile.open(file_path, 'r:') as tar_ref:
                tar_ref.extractall(extract_to)
                extracted_files = tar_ref.getnames()
                logger.info(f"تم استخراج {len(extracted_files)} ملف من الأرشيف TAR")
                return True, extracted_files
                
        else:
            logger.error(f"نوع الأرشيف غير مدعوم: {file_path}")
            return False, []
            
    except Exception as e:
        logger.error(f"فشل فك الضغط: {e}")
        return False, []


def get_python_files(directory):
    """الحصول على جميع ملفات البايثون في المجلد مع معلومات مفصلة"""
    python_files = []
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    python_files.append(full_path)
                    
        # تسجيل معلومات الملفات
        logger.info(f"تم العثور على {len(python_files)} ملف بايثون في {directory}")
        for py_file in python_files[:5]:  # تسجيل أول 5 ملفات فقط
            logger.info(f"ملف بايثون: {py_file}")
            
    except Exception as e:
        logger.error(f"فشل البحث عن ملفات بايثون: {e}")
    
    return python_files

# ======= نظام تثبيت المتطلبات المحسّن النهائي ======= #


# ======= دوال تنظيف السجلات ======= #
async def clean_bot_logs(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """تنظيف سجلات البوت"""
    query = update.callback_query
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
    log_file = bot_info['log_file']

    try:
        if os.path.exists(log_file):
            # حفظ نسخة احتياطية قبل المسح
            backup_dir = os.path.join(LOG_FOLDER, 'backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            backup_file = os.path.join(backup_dir, f"{actual_bot_name}_{int(time.time())}.log")
            shutil.copy2(log_file, backup_file)
            
            # مسح محتوى الملف
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("")
            
            # مسح الملفات الاحتياطية القديمة (تحتفظ بآخر 5 نسخ فقط)
            cleanup_old_backups(backup_dir, actual_bot_name, 5)
            
            await query.edit_message_text(f"✅ تم تنظيف سجلات البوت {actual_bot_name} بنجاح!\n\n📁 تم حفظ نسخة احتياطية")
        else:
            await query.edit_message_text("📝 لا توجد سجلات للتنظيف")

    except Exception as e:
        await query.edit_message_text(f"❌ فشل تنظيف السجلات: {str(e)}")

def cleanup_old_backups(backup_dir, bot_name, keep_count=5):
    """مسح النسخ الاحتياطية القديمة"""
    try:
        # البحث عن جميع النسخ الاحتياطية للبوت
        backup_files = []
        for file in os.listdir(backup_dir):
            if file.startswith(f"{bot_name}_") and file.endswith('.log'):
                file_path = os.path.join(backup_dir, file)
                backup_files.append((file_path, os.path.getctime(file_path)))
        
        # ترتيب حسب تاريخ الإنشاء (الأقدم أولاً)
        backup_files.sort(key=lambda x: x[1])
        
        # مسح الملفات الزائدة
        while len(backup_files) > keep_count:
            old_file, _ = backup_files.pop(0)
            try:
                os.remove(old_file)
                logger.info(f"تم مسح النسخة الاحتياطية القديمة: {old_file}")
            except Exception as e:
                logger.error(f"فشل مسح النسخة الاحتياطية {old_file}: {e}")
                
    except Exception as e:
        logger.error(f"خطأ في تنظيف النسخ الاحتياطية: {e}")

async def clean_all_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """تنظيف جميع سجلات البوتات"""
    user_id = update.effective_user.id

    load_data()

    if user_id not in user_bots or not user_bots[user_id]['bots']:
        await update.message.reply_text("❌ ليس لديك أي بوتات حتى الآن.")
        return

    cleaned_count = 0
    total_bots = len(user_bots[user_id]['bots'])

    for bot_name, bot_info in user_bots[user_id]['bots'].items():
        log_file = bot_info['log_file']
        
        try:
            if os.path.exists(log_file):
                # حفظ نسخة احتياطية
                backup_dir = os.path.join(LOG_FOLDER, 'backups')
                os.makedirs(backup_dir, exist_ok=True)
                backup_file = os.path.join(backup_dir, f"{bot_name}_{int(time.time())}.log")
                shutil.copy2(log_file, backup_file)
                
                # مسح المحتوى
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write("")
                
                cleaned_count += 1
                
        except Exception as e:
            logger.error(f"فشل تنظيف سجلات البوت {bot_name}: {e}")

    await update.message.reply_text(f"✅ تم تنظيف سجلات {cleaned_count} من أصل {total_bots} بوت")

async def show_logs_statistics(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض إحصائيات السجلات"""
    query = update.callback_query
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
    log_file = bot_info['log_file']

    try:
        stats_text = f"📊 **إحصائيات سجلات البوت: {actual_bot_name}**\n\n"

        if os.path.exists(log_file):
            file_size = os.path.getsize(log_file)
            stats_text += f"📁 حجم ملف السجل: {file_size / 1024:.2f} KB\n"
            
            if file_size > 0:
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    stats_text += f"📝 عدد الأسطر: {len(lines)}\n"
                    
                    # حساب عدد الأسطر في آخر 24 ساعة (افتراضي)
                    recent_lines = len([line for line in lines if '202' in line[:4]])  # تبسيط
                    stats_text += f"🕒 الأسعار الحديثة: {recent_lines}\n"
            else:
                stats_text += "📝 الملف فارغ\n"
        else:
            stats_text += "📝 لا يوجد ملف سجل\n"

        # إحصائيات النسخ الاحتياطية
        backup_dir = os.path.join(LOG_FOLDER, 'backups')
        if os.path.exists(backup_dir):
            backup_files = [f for f in os.listdir(backup_dir) if f.startswith(f"{actual_bot_name}_")]
            stats_text += f"📦 النسخ الاحتياطية: {len(backup_files)}\n"
            
            if backup_files:
                total_backup_size = sum(os.path.getsize(os.path.join(backup_dir, f)) for f in backup_files)
                stats_text += f"💾 حجم النسخ: {total_backup_size / 1024 / 1024:.2f} MB\n"

        keyboard = [
            [InlineKeyboardButton("🧹 تنظيف السجلات", callback_data=f"clean_logs_{actual_bot_name}")],
            [InlineKeyboardButton("📋 عرض السجلات", callback_data=f"logs_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"file_manager_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(stats_text, reply_markup=reply_markup, parse_mode='HTML')

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ: {str(e)}")

# ======= نظام التحكم في الاستضافة ======= #
async def terminal_control(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """فتح واجهة التحكم في الاستضافة"""
    user_id = update.effective_user.id
    
    # التحقق من صلاحية المستخدم (يمكنك تعديل هذا حسب احتياجك)
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ هذا الأمر متاح للمشرف فقط")
        return

    keyboard = [
        [InlineKeyboardButton("📁 عرض الملفات", callback_data="term_ls")],
        [InlineKeyboardButton("📊 حالة النظام", callback_data="term_status")],
        [InlineKeyboardButton("🐍 إدارة بايثون", callback_data="term_python")],
        [InlineKeyboardButton("📦 إدارة الحزم", callback_data="term_packages")],
        [InlineKeyboardButton("🔧 أوامر مخصصة", callback_data="term_custom")],
        [InlineKeyboardButton("❌ إغلاق", callback_data="term_close")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "🖥️ **وحدة التحكم في الاستضافة**\n\n"
        "اختر نوع الأمر الذي تريد تنفيذه:\n\n"
        "⚠️ **تحذير:** هذه الأوامر تنفذ مباشرة على الخادم!\n"
        "استخدمها بحذر شديد.",
        reply_markup=reply_markup,
        parse_mode='HTML'
    )

async def execute_terminal_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """تنفيذ أوامر الاستضافة"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    
    if user_id != ADMIN_ID:
        await query.edit_message_text("❌ هذا الأمر متاح للمشرف فقط")
        return

    data = query.data

    if data == "term_ls":
        await execute_command_and_send(update, context, "ls -la", "📁 عرض الملفات")

    elif data == "term_status":
        await execute_command_and_send(update, context, "top -bn1 | head -20", "📊 حالة النظام")

    elif data == "term_python":
        keyboard = [
            [InlineKeyboardButton("🐍 إصدار بايثون", callback_data="cmd_python_version")],
            [InlineKeyboardButton("📦 قائمة الحزم", callback_data="cmd_pip_list")],
            [InlineKeyboardButton("🔍 معلومات النظام", callback_data="cmd_system_info")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="term_back")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("🐍 **إدارة بايثون والحزم**", reply_markup=reply_markup)

    elif data == "term_packages":
        keyboard = [
            [InlineKeyboardButton("📦 تحديث pip", callback_data="cmd_pip_upgrade")],
            [InlineKeyboardButton("🔍 البحث عن حزمة", callback_data="cmd_search_package")],
            [InlineKeyboardButton("📊 حجم الحزم", callback_data="cmd_pip_size")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="term_back")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("📦 **إدارة الحزم**", reply_markup=reply_markup)

    elif data == "term_custom":
        context.user_data['waiting_for_command'] = True
        await query.edit_message_text(
            "⌨️ **أدخل الأمر الذي تريد تنفيذه:**\n\n"
            "مثال:\n"
            "• `pwd` - المسار الحالي\n"
            "• `df -h` - مساحة التخزين\n"
            "• `free -h` - الذاكرة\n"
            "• `ps aux | grep python` - العمليات\n\n"
            "⚠️ **تحذير:** الأوامر تنفذ بكامل الصلاحيات!"
        )

    elif data == "term_close":
        await query.edit_message_text("✅ تم إغلاق وحدة التحكم")

    elif data == "term_back":
        await terminal_control(update, context)

    # الأوامر الفرعية
    elif data == "cmd_python_version":
        await execute_command_and_send(update, context, "python --version", "🐍 إصدار بايثون")

    elif data == "cmd_pip_list":
        await execute_command_and_send(update, context, "pip list", "📦 قائمة الحزم")

    elif data == "cmd_system_info":
        await execute_command_and_send(update, context, "uname -a", "🔍 معلومات النظام")

    elif data == "cmd_pip_upgrade":
        await execute_command_and_send(update, context, "python -m pip install --upgrade pip", "📦 تحديث pip")

    elif data == "cmd_pip_size":
        await execute_command_and_send(update, context, "pip list --format=freeze | wc -l", "📊 عدد الحزم")

async def execute_command_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE, command: str, title: str):
    """تنفيذ أمر وإرسال النتيجة"""
    query = update.callback_query
    
    try:
        await query.edit_message_text(f"⏳ جاري تنفيذ: `{command}`")
        
        # تنفيذ الأمر
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=30)
        
        result_text = f"🎯 **{title}**\n\n"
        result_text += f"```bash\n$ {command}\n```\n\n"
        
        if stdout:
            result_text += f"📤 **الإخراج:**\n```\n{stdout}\n```\n"
        
        if stderr:
            result_text += f"❌ **الأخطاء:**\n```\n{stderr}\n```\n"
        
        result_text += f"\n📊 **كود الخروج:** {process.returncode}"
        
        # تقسيم النتيجة إذا كانت طويلة
        if len(result_text) > 4000:
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for i, part in enumerate(parts):
                if i == 0:
                    await query.edit_message_text(part, parse_mode='HTML')
                else:
                    await context.bot.send_message(query.message.chat_id, part, parse_mode='HTML')
        else:
            await query.edit_message_text(result_text, parse_mode='HTML')
            
    except subprocess.TimeoutExpired:
        await query.edit_message_text(f"⏰ انتهى الوقت المحدد للأمر: `{command}`")
    except Exception as e:
        await query.edit_message_text(f"❌ خطأ في التنفيذ: {str(e)}")

async def handle_custom_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة الأوامر المخصصة من المستخدم"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ هذا الأمر متاح للمشرف فقط")
        return

    if not context.user_data.get('waiting_for_command'):
        return

    command = update.message.text.strip()
    
    if command.lower() in ['exit', 'quit', 'cancel', 'إلغاء']:
        context.user_data['waiting_for_command'] = False
        await update.message.reply_text("✅ تم إلغاء وضع الأوامر")
        return

    # تنفيذ الأمر
    try:
        await update.message.reply_text(f"⏳ جاري تنفيذ: `{command}`")
        
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=60)  # وقت أطول للأوامر المخصصة
        
        result_text = f"🎯 **نتيجة الأمر:** `{command}`\n\n"
        
        if stdout:
            # تقصير الإخراج الطويل
            if len(stdout) > 3000:
                stdout = stdout[:3000] + "\n... (تم تقصير الإخراج)"
            result_text += f"📤 **الإخراج:**\n```\n{stdout}\n```\n"
        
        if stderr:
            if len(stderr) > 3000:
                stderr = stderr[:3000] + "\n... (تم تقصير الأخطاء)"
            result_text += f"❌ **الأخطاء:**\n```\n{stderr}\n```\n"
        
        result_text += f"\n📊 **كود الخروج:** {process.returncode}"
        
        if len(result_text) > 4000:
            parts = [result_text[i:i+4000] for i in range(0, len(result_text), 4000)]
            for part in parts:
                await update.message.reply_text(part, parse_mode='HTML')
        else:
            await update.message.reply_text(result_text, parse_mode='HTML')
            
    except subprocess.TimeoutExpired:
        await update.message.reply_text(f"⏰ انتهى الوقت المحدد للأمر: `{command}`")
    except Exception as e:
        await update.message.reply_text(f"❌ خطأ في التنفيذ: {str(e)}")

    # البقاء في وضع الأوامر
    await update.message.reply_text(
        "⌨️ **أدخل الأمر التالي أو اكتب 'إلغاء' للخروج:**\n\n"
        "⚠️ **تحذير:** الأوامر تنفذ بكامل الصلاحيات!"
    )


async def install_requirements_real_time(requirements_file, bot_lib_folder, user_id, chat_id, bot_name, bot_instance):
    """تثبيت المتطلبات حقيقياً مع إصلاح مشكلة المسار"""
    try:
        # إرسال رسالة بدء التثبيت
        status_message = await bot_instance.send_message(
            chat_id, 
            f"📦 جاري تثبيت متطلبات البوت {bot_name}..."
        )
        
        # 🔧 الإصلاح: التحقق المكثف من المسار
        logger.info(f"🔍 فحص المسار: {requirements_file}")
        logger.info(f"📁 المجلد: {bot_lib_folder}")
        
        # التحقق من وجود المجلد وإنشاؤه إذا لزم الأمر
        os.makedirs(bot_lib_folder, exist_ok=True)
        logger.info(f"✅ تأكد من وجود المجلد: {os.path.exists(bot_lib_folder)}")
        
        # 🔍 فحص شامل للملف
        if not os.path.exists(requirements_file):
            error_msg = f"❌ ملف المتطلبات غير موجود:\n{requirements_file}"
            logger.error(error_msg)
            
            # محاولة إنشاء ملف جديد
            try:
                default_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
                
                with open(requirements_file, 'w', encoding='utf-8') as f:
                    f.write(default_content)
                logger.info(f"✅ تم إنشاء ملف متطلبات جديد: {requirements_file}")
                
                await status_message.edit_text("📝 تم إنشاء ملف المتطلبات، جاري التثبيت...")
            except Exception as e:
                error_msg = f"❌ فشل إنشاء الملف: {str(e)}"
                logger.error(error_msg)
                await status_message.edit_text(error_msg)
                return False, error_msg
        
        # ✅ الملف موجود الآن، التحقق من المحتوى
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                requirements_list = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
            
            if not requirements_list:
                await status_message.edit_text("⚠️ ملف المتطلبات فارغ")
                return False, "ملف المتطلبات فارغ"
                
            await status_message.edit_text(f"🚀 جاري تثبيت {len(requirements_list)} مكتبة...")
            
        except Exception as e:
            error_msg = f"❌ خطأ في قراءة الملف: {str(e)}"
            await status_message.edit_text(error_msg)
            return False, error_msg

        # 🛠️ بدء التثبيت
        try:
            # التأكد من المسار مرة أخرى قبل التثبيت
            if not os.path.exists(requirements_file):
                await status_message.edit_text("❌ فقد الملف أثناء العملية!")
                return False, "فقد الملف"
            
            # استخدام المسار المطلق للتأكد
            abs_requirements_file = os.path.abspath(requirements_file)
            abs_lib_folder = os.path.abspath(bot_lib_folder)
            
            logger.info(f"📍 المسار المطلق للمتطلبات: {abs_requirements_file}")
            logger.info(f"📍 المسار المطلق للمكتبات: {abs_lib_folder}")
            
            # تنفيذ أمر التثبيت
            process = subprocess.Popen(
                [sys.executable, '-m', 'pip', 'install', '-r', abs_requirements_file, '--no-cache-dir'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=abs_lib_folder
            )

            # قراءة المخرجات
            output_lines = []
            
            def read_output(stream, lines):
                for line in iter(stream.readline, ''):
                    if line.strip():
                        lines.append(line.strip())
            
            stdout_thread = threading.Thread(target=read_output, args=(process.stdout, output_lines))
            stderr_thread = threading.Thread(target=read_output, args=(process.stderr, output_lines))
            
            stdout_thread.start()
            stderr_thread.start()

            # الانتظار مع تحديثات
            last_update = time.time()
            while process.poll() is None:
                time.sleep(2)
                if time.time() - last_update > 15:
                    current_time = datetime.now().strftime('%H:%M:%S')
                    try:
                        await status_message.edit_text(f"⏳ جاري التثبيت...\n🕒 {current_time}\n📊 تم معالجة {len(output_lines)} سطر")
                    except:
                        pass
                    last_update = time.time()

            # الانتظار لإنهاء القراءة
            stdout_thread.join(timeout=10)
            stderr_thread.join(timeout=10)

            # معالجة النتيجة
            if process.returncode == 0:
                # النجاح
                installed_packages = []
                for line in output_lines:
                    if 'Successfully installed' in line:
                        packages = line.split('Successfully installed')[-1].strip()
                        installed_packages.extend([pkg.strip() for pkg in packages.split() if pkg.strip()])
                
                success_msg = f"✅ تم تثبيت متطلبات {bot_name} بنجاح!\n\n"
                if installed_packages:
                    success_msg += f"📦 تم تثبيت {len(installed_packages)} مكتبة\n"
                    success_msg += "🎉 البوت جاهز للتشغيل!"
                
                await status_message.edit_text(success_msg)
                return True, "تم التثبيت بنجاح"
                
            else:
                # الفشل
                error_output = "\n".join(output_lines[-10:]) if output_lines else "لا توجد تفاصيل"
                error_msg = f"❌ فشل التثبيت:\n{error_output}"
                await status_message.edit_text(error_msg)
                return False, error_output

        except Exception as e:
            error_msg = f"❌ خطأ أثناء التثبيت: {str(e)}"
            logger.error(error_msg)
            await status_message.edit_text(error_msg)
            return False, error_msg

    except Exception as e:
        error_msg = f"❌ خطأ غير متوقع: {str(e)}"
        logger.error(error_msg)
        try:
            await bot_instance.send_message(chat_id, error_msg)
        except:
            pass
        return False, error_msg


async def show_all_extracted_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض جميع الملفات المستخرجة"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    
    if user_id not in user_sessions or 'extracted_files' not in user_sessions[user_id]:
        await query.edit_message_text("❌ لا توجد ملفات مستخرجة لعرضها")
        return FILE_SELECTION

    extracted_files = user_sessions[user_id]['extracted_files']
    python_files = user_sessions[user_id]['python_files']

    # تقسيم القائمة إذا كانت طويلة
    files_text = "📁 **جميع الملفات المستخرجة:**\n\n"
    
    for i, file_path in enumerate(extracted_files[:50]):  # عرض أول 50 ملف فقط
        icon = "🐍" if any(file_path.endswith(py_file) for py_file in [f.endswith('.py') for f in python_files]) else "📄"
        files_text += f"{icon} {file_path}\n"

    if len(extracted_files) > 50:
        files_text += f"\n... و {len(extracted_files) - 50} ملفات أخرى"

    files_text += f"\n\n🐍 **ملفات بايثون ({len(python_files)}):**\n"
    for py_file in python_files:
        rel_path = os.path.relpath(py_file, user_sessions[user_id]['temp_dir'])
        files_text += f"• {rel_path}\n"

    await query.edit_message_text(files_text)

    # إعادة عرض لوحة الاختيار
    keyboard = []
    for i, file_path in enumerate(python_files):
        file_name = os.path.basename(file_path)
        rel_path = os.path.relpath(file_path, user_sessions[user_id]['temp_dir'])
        keyboard.append([InlineKeyboardButton(f"🐍 {file_name} ({rel_path})", callback_data=f"select_file_{i}")])

    keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data="back_to_selection")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    await context.bot.send_message(
        query.message.chat_id,
        "اختر الملف الرئيسي لتشغيله:",
        reply_markup=reply_markup
    )



async def install_requirements_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """معالجة تثبيت متطلبات البوت - الإصدار المصحح"""
    query = update.callback_query

    if query is None:
        return CHOOSE_ACTION

    await query.answer()

    user_id = query.from_user.id
    chat_id = query.message.chat_id

    load_data()

    if not await check_bot_exists(user_id, bot_name):
        await query.edit_message_text("❌ البوت غير موجود!")
        return CHOOSE_ACTION

    # البحث عن اسم البوت الفعلي
    actual_bot_name = None
    for existing_bot in user_bots[user_id]['bots'].keys():
        if existing_bot.lower() == bot_name.lower():
            actual_bot_name = existing_bot
            break

    if not actual_bot_name:
        await query.edit_message_text("❌ البوت غير موجود!")
        return CHOOSE_ACTION

    bot_info = user_bots[user_id]['bots'][actual_bot_name]
    
    # 🔧 الإصلاح: استخدام المسار من bot_info مباشرة
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')
    
    # تسجيل المعلومات للتصحيح
    logger.info(f"🔍 معلومات التثبيت:")
    logger.info(f"   المستخدم: {user_id}")
    logger.info(f"   البوت: {actual_bot_name}")
    logger.info(f"   مسار المكتبات: {bot_info['lib_folder']}")
    logger.info(f"   ملف المتطلبات: {requirements_file}")
    logger.info(f"   الملف موجود: {os.path.exists(requirements_file)}")

    # التحقق من وجود الملف
    if not os.path.exists(requirements_file):
        await query.edit_message_text(
            f"❌ ملف المتطلبات غير موجود!\n"
            f"المسار: `{requirements_file}`\n\n"
            f"جاري إنشاء ملف جديد..."
        )
        
        # إنشاء الملف تلقائياً
        try:
            os.makedirs(bot_info['lib_folder'], exist_ok=True)
            default_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
            
            with open(requirements_file, 'w', encoding='utf-8') as f:
                f.write(default_content)
            
            bot_info['has_requirements'] = True
            save_data()
            
            await query.edit_message_text("✅ تم إنشاء ملف المتطلبات، جاري التثبيت...")
        except Exception as e:
            await query.edit_message_text(f"❌ فشل إنشاء الملف: {str(e)}")
            return CHOOSE_ACTION

    # بدء التثبيت
    await query.edit_message_text(f"🚀 بدء تثبيت متطلبات {actual_bot_name}...")

    # التشغيل في مهمة منفصلة
    asyncio.create_task(
        run_installation_process(requirements_file, bot_info['lib_folder'], user_id, chat_id, actual_bot_name, context.bot, bot_info)
    )

    return CHOOSE_ACTION


async def fix_requirements_now(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إصلاح فوري لمشكلة المتطلبات"""
    user_id = update.effective_user.id
    bot_name = "app_55"  # أو يمكن جعله ديناميكياً
    
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
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')
    
    # معلومات التصحيح
    debug_info = f"""
🔍 **تصحيح متطلبات {actual_bot_name}:**

📁 مسار المكتبات: `{bot_info['lib_folder']}`
📄 ملف المتطلبات: `{requirements_file}`
✅ المجلد موجود: `{os.path.exists(bot_info['lib_folder'])}`
✅ الملف موجود: `{os.path.exists(requirements_file)}`
"""

    if os.path.exists(requirements_file):
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
                debug_info += f"📊 عدد المكتبات: {len(lines)}"
        except Exception as e:
            debug_info += f"❌ خطأ في القراءة: {e}"
    else:
        # إنشاء الملف
        try:
            os.makedirs(bot_info['lib_folder'], exist_ok=True)
            content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
            
            with open(requirements_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            bot_info['has_requirements'] = True
            save_data()
            
            debug_info += "\n✅ تم إنشاء ملف المتطلبات بنجاح!"
            
        except Exception as e:
            debug_info += f"\n❌ فشل إنشاء الملف: {e}"

    await update.message.reply_text(debug_info, parse_mode='HTML')


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
        await bot_instance.send_message(chat_id, f"❌ فشل عملية التثبيت: {str(e)}")

async def handle_requirements_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة رفع ملف المتطلبات - الإصدار النهائي"""
    user_id = update.effective_user.id

    if not update.message.document:
        await update.message.reply_text("❌ يرجى رفع ملف requirements.txt")
        return REQUIREMENTS_SETUP

    document = update.message.document

    if not document.file_name.lower().endswith('.txt'):
        await update.message.reply_text("❌ يرجى رفع ملف نصي (txt) فقط")
        return REQUIREMENTS_SETUP

    load_data()

    # التحقق من وجود البوت
    bot_name = context.user_data.get('uploading_req_to')
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
        # إنشاء مجلد المكتبات إذا لم يكن موجوداً
        os.makedirs(bot_info['lib_folder'], exist_ok=True)

        # تحميل الملف
        file = await context.bot.get_file(document.file_id)
        await file.download_to_drive(requirements_file)

        # التحقق من صحة الملف
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                requirements_list = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
            
            if not requirements_list:
                await update.message.reply_text("⚠️ ملف المتطلبات فارغ أو لا يحتوي على مكتبات صالحة")
                os.remove(requirements_file)
                return REQUIREMENTS_SETUP
                
        except Exception as e:
            await update.message.reply_text(f"❌ ملف المتطلبات غير صالح: {str(e)}")
            if os.path.exists(requirements_file):
                os.remove(requirements_file)
            return REQUIREMENTS_SETUP

        bot_info['has_requirements'] = True
        bot_info['requirements_installed'] = False
        save_data()

        keyboard = [
            [InlineKeyboardButton("🚀 تثبيت المتطلبات الآن", callback_data=f"install_req_{actual_bot_name}")],
            [InlineKeyboardButton("📋 عرض المتطلبات", callback_data=f"view_req_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"lib_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        success_message = f"✅ تم رفع ملف المتطلبات للبوت {actual_bot_name} بنجاح!\n\n"
        success_message += f"📊 تم العثور على {len(requirements_list)} مكتبة\n"
        success_message += "يمكنك الآن تثبيت المتطلبات أو عرضها."

        await update.message.reply_text(success_message, reply_markup=reply_markup)

    except Exception as e:
        await update.message.reply_text(f"❌ حدث خطأ أثناء رفع الملف: {str(e)}")

    return ConversationHandler.END

async def view_requirements_detailed(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض متطلبات البوت بشكل مفصل - الإصدار النهائي"""
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

    if not os.path.exists(requirements_file):
        await query.edit_message_text("❌ لا يوجد ملف requirements.txt لهذا البوت.")
        return

    try:
        with open(requirements_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        if not content:
            await query.edit_message_text("📄 ملف المتطلبات فارغ.")
            return

        # حساب عدد المكتبات
        requirements_list = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
        
        # تنظيف المحتوى من الرموز الخاصة
        clean_content = html.escape(content)
        
        # تقسيم المحتوى إذا كان طويلاً
        if len(clean_content) > 3000:
            parts = [clean_content[i:i+3000] for i in range(0, len(clean_content), 3000)]
            for i, part in enumerate(parts):
                part_text = f"📋 جزء {i+1} من {len(parts)} - متطلبات {actual_bot_name} ({len(requirements_list)} مكتبة):\n\n<code>{part}</code>"
                if i == 0:
                    await query.edit_message_text(part_text, parse_mode='HTML')
                else:
                    await context.bot.send_message(query.message.chat_id, part_text, parse_mode='HTML')
        else:
            requirements_text = f"📋 متطلبات البوت {actual_bot_name} ({len(requirements_list)} مكتبة):\n\n<code>{clean_content}</code>"
            await query.edit_message_text(requirements_text, parse_mode='HTML')

        # إضافة أزرار الإجراءات
        keyboard = [
            [InlineKeyboardButton("🚀 تثبيت المتطلبات", callback_data=f"install_req_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"lib_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(
            query.message.chat_id,
            f"📊 تم العثور على {len(requirements_list)} مكتبة في الملف.\nاختر الإجراء المناسب:",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ أثناء قراءة الملف: {str(e)}")

# ======= دوال مساعدة للبوتات ======= #


# ======= دوال إدارة ملفات البوت ======= #
async def list_bot_files(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض ملفات البوت"""
    query = update.callback_query
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
    
    # الحصول على جميع الملفات في مجلد المشروع
    project_path = bot_info.get('project_path') or os.path.dirname(bot_info['file_path'])
    
    if not os.path.exists(project_path):
        await query.edit_message_text("❌ مجلد المشروع غير موجود!")
        return

    try:
        # جمع معلومات الملفات
        all_files = []
        total_size = 0
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                file_size = os.path.getsize(file_path)
                total_size += file_size
                
                all_files.append({
                    'path': file_path,
                    'rel_path': rel_path,
                    'size': file_size,
                    'is_python': file.endswith('.py')
                })

        # ترتيب الملفات بحيث تكون ملفات البايثون أولاً
        all_files.sort(key=lambda x: (not x['is_python'], x['rel_path']))

        # إنشاء قائمة الملفات
        files_text = f"📁 **ملفات البوت: {actual_bot_name}**\n\n"
        files_text += f"📊 إجمالي الملفات: {len(all_files)}\n"
        files_text += f"💾 الحجم الإجمالي: {total_size / 1024:.2f} KB\n\n"
        
        # عرض الملفات (أول 20 ملف)
        for i, file_info in enumerate(all_files[:20]):
            icon = "🐍" if file_info['is_python'] else "📄"
            size_kb = file_info['size'] / 1024
            files_text += f"{icon} `{file_info['rel_path']}` ({size_kb:.1f} KB)\n"

        if len(all_files) > 20:
            files_text += f"\n... و {len(all_files) - 20} ملفات أخرى"

        # أزرار التحكم
        keyboard = [
            [InlineKeyboardButton("📥 تحميل ملف", callback_data=f"download_file_{actual_bot_name}")],
            [InlineKeyboardButton("🗑️ حذف ملف", callback_data=f"delete_file_{actual_bot_name}")],
            [InlineKeyboardButton("📋 عرض جميع الملفات", callback_data=f"show_all_files_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"settings_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(files_text, reply_markup=reply_markup, parse_mode='HTML')

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ أثناء عرض الملفات: {str(e)}")

async def download_bot_file(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """تحميل ملف من البوت"""
    query = update.callback_query
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
    project_path = bot_info.get('project_path') or os.path.dirname(bot_info['file_path'])

    # الحصول على قائمة الملفات لعرضها للمستخدم
    try:
        files_list = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                files_list.append((rel_path, file_path))

        if not files_list:
            await query.edit_message_text("❌ لا توجد ملفات للتحميل!")
            return

        # إنشاء لوحة اختيار الملفات
        keyboard = []
        for rel_path, full_path in files_list[:20]:  # عرض أول 20 ملف فقط
            file_name = os.path.basename(rel_path)
            keyboard.append([InlineKeyboardButton(f"📄 {file_name}", callback_data=f"dl_{actual_bot_name}_{hash(rel_path)}")])
            context.user_data[f"file_path_{hash(rel_path)}"] = full_path

        keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data=f"file_manager_{actual_bot_name}")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"📥 اختر الملف للتحميل من بوت {actual_bot_name}:",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ: {str(e)}")

async def handle_file_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة تحميل الملف"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    data = query.data

    if data.startswith("dl_"):
        parts = data.split('_')
        bot_name = parts[1]
        file_hash = int(parts[2])

        file_path = context.user_data.get(f"file_path_{file_hash}")

        if not file_path or not os.path.exists(file_path):
            await query.edit_message_text("❌ الملف غير موجود!")
            return

        try:
            file_size = os.path.getsize(file_path)
            
            if file_size > 50 * 1024 * 1024:  # 50MB limit for Telegram
                await query.edit_message_text("❌ حجم الملف كبير جداً للتحميل عبر التليجرام (الحد: 50MB)")
                return

            # إرسال الملف
            with open(file_path, 'rb') as file:
                await context.bot.send_document(
                    chat_id=query.message.chat_id,
                    document=file,
                    filename=os.path.basename(file_path),
                    caption=f"📄 {os.path.basename(file_path)}\n🤖 {bot_name}"
                )

            await query.edit_message_text("✅ تم إرسال الملف بنجاح!")

        except Exception as e:
            await query.edit_message_text(f"❌ فشل تحميل الملف: {str(e)}")

async def delete_bot_file(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """حذف ملف من البوت"""
    query = update.callback_query
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
    project_path = bot_info.get('project_path') or os.path.dirname(bot_info['file_path'])

    # الحصول على قائمة الملفات
    try:
        files_list = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                # منع حذف الملف الرئيسي للبوت
                if file_path != bot_info['file_path']:
                    files_list.append((rel_path, file_path))

        if not files_list:
            await query.edit_message_text("❌ لا توجد ملفات يمكن حذفها!")
            return

        # إنشاء لوحة اختيار الملفات
        keyboard = []
        for rel_path, full_path in files_list[:20]:  # عرض أول 20 ملف فقط
            file_name = os.path.basename(rel_path)
            keyboard.append([InlineKeyboardButton(f"🗑️ {file_name}", callback_data=f"del_{actual_bot_name}_{hash(rel_path)}")])
            context.user_data[f"del_path_{hash(rel_path)}"] = full_path

        keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data=f"file_manager_{actual_bot_name}")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"🗑️ اختر الملف لحذفه من بوت {actual_bot_name}:\n\n"
            "⚠️ تحذير: لا يمكن التراجع عن الحذف!",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ: {str(e)}")

async def handle_file_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة حذف الملف"""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    data = query.data

    if data.startswith("del_"):
        parts = data.split('_')
        bot_name = parts[1]
        file_hash = int(parts[2])

        file_path = context.user_data.get(f"del_path_{file_hash}")

        if not file_path or not os.path.exists(file_path):
            await query.edit_message_text("❌ الملف غير موجود!")
            return

        try:
            # التأكد من أن الملف ليس الملف الرئيسي للبوت
            load_data()
            bot_info = user_bots[user_id]['bots'][bot_name]
            if file_path == bot_info['file_path']:
                await query.edit_message_text("❌ لا يمكن حذف الملف الرئيسي للبوت!")
                return

            # حذف الملف
            os.remove(file_path)
            await query.edit_message_text(f"✅ تم حذف الملف: {os.path.basename(file_path)}")

        except Exception as e:
            await query.edit_message_text(f"❌ فشل حذف الملف: {str(e)}")

async def show_all_bot_files(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """عرض جميع ملفات البوت بشكل مفصل"""
    query = update.callback_query
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
    project_path = bot_info.get('project_path') or os.path.dirname(bot_info['file_path'])

    try:
        all_files = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, project_path)
                file_size = os.path.getsize(file_path)
                all_files.append((rel_path, file_size, file.endswith('.py')))

        # تقسيم الملفات إلى أجزاء إذا كانت كثيرة
        files_text = f"📁 **جميع ملفات البوت: {actual_bot_name}**\n\n"
        
        for i, (rel_path, size, is_python) in enumerate(all_files):
            icon = "🐍" if is_python else "📄"
            size_kb = size / 1024
            files_text += f"{icon} `{rel_path}` ({size_kb:.1f} KB)\n"
            
            if len(files_text) > 3000:  # حد التليجرام
                files_text += f"\n... و {len(all_files) - i - 1} ملفات أخرى"
                break

        # إرسال الملفات كرسالة منفصلة
        await context.bot.send_message(
            query.message.chat_id,
            files_text,
            parse_mode='HTML'
        )

        # إعادة عرض لوحة التحكم
        keyboard = [
            [InlineKeyboardButton("📥 تحميل ملف", callback_data=f"download_file_{actual_bot_name}")],
            [InlineKeyboardButton("🗑️ حذف ملف", callback_data=f"delete_file_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"file_manager_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"📊 تم عرض {len(all_files)} ملف من بوت {actual_bot_name}",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ حدث خطأ: {str(e)}")


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
    """معالجة أمر /start مع الإضافات الجديدة"""
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
        [KeyboardButton("🧹 تنظيف السجلات"), KeyboardButton("🖥️ وحدة التحكم")],  # الأزرار الجديدة
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
        "🌐 استيراد مباشر من GitHub\n"
        "🧹 تنظيف السجلات تلقائياً\n"  # الإضافة الجديدة
        "🖥️ تحكم كامل في الاستضافة\n\n"  # الإضافة الجديدة
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
    """معالجة رفع الملفات المضغوطة مع استخراج كامل"""
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

        # فحص الأمان
        if protection_enabled and not is_admin(user_id):
            is_malicious, activity, threat_type = scan_zip_for_malicious_code(file_path, user_id)
            if is_malicious:
                if threat_type == "encrypted":
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه مشفر.")
                else:
                    await update.message.reply_text("⛔ تم رفض ملفك لأنه يحتوي على ثغرات أمنية.")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return ZIP_UPLOAD

        # فك الضغط
        success, extracted_files = extract_archive(file_path, temp_dir)
        if not success:
            await update.message.reply_text("❌ فشل في فك ضغط الملف. قد يكون الملف تالفاً.")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return ZIP_UPLOAD

        # إرسال تقرير بالملفات المستخرجة
        if extracted_files:
            files_list = "\n".join([f"📄 {file}" for file in extracted_files[:10]])  # عرض أول 10 ملفات فقط
            if len(extracted_files) > 10:
                files_list += f"\n... و {len(extracted_files) - 10} ملفات أخرى"
            
            await update.message.reply_text(
                f"✅ تم فك الضغط بنجاح!\n"
                f"📊 تم استخراج {len(extracted_files)} ملف\n\n"
                f"الملفات المستخرجة:\n{files_list}"
            )

        # البحث عن ملفات بايثون
        python_files = get_python_files(temp_dir)

        if not python_files:
            await update.message.reply_text(
                "❌ لم يتم العثور على أي ملفات بايثون في الأرشيف.\n"
                "الملفات المستخرجة:\n" + "\n".join(extracted_files[:20])
            )
            shutil.rmtree(temp_dir, ignore_errors=True)
            return ZIP_UPLOAD

        if user_id not in user_sessions:
            user_sessions[user_id] = {}

        user_sessions[user_id]['temp_dir'] = temp_dir
        user_sessions[user_id]['python_files'] = python_files
        user_sessions[user_id]['extracted_files'] = extracted_files

        # عرض خيارات الملفات
        keyboard = []
        for i, file_path in enumerate(python_files):
            file_name = os.path.basename(file_path)
            rel_path = os.path.relpath(file_path, temp_dir)
            keyboard.append([InlineKeyboardButton(f"🐍 {file_name} ({rel_path})", callback_data=f"select_file_{i}")])

        # إضافة خيار لعرض جميع الملفات
        keyboard.append([InlineKeyboardButton("📁 عرض جميع الملفات المستخرجة", callback_data="show_all_files")])
        keyboard.append([InlineKeyboardButton("❌ إلغاء", callback_data="cancel_selection")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            f"✅ تم فك الضغط بنجاح!\n"
            f"📊 تم العثور على {len(python_files)} ملف بايثون\n\n"
            "اختر الملف الرئيسي لتشغيله:",
            reply_markup=reply_markup
        )
        return FILE_SELECTION

    except Exception as e:
        error_msg = str(e)
        logger.error(f"خطأ في معالجة الملف المضغوط: {error_msg}")
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
        [InlineKeyboardButton("📁 إدارة ملفات البوت", callback_data=f"file_manager_{actual_bot_name}")], 
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
        else:
            keyboard.append([InlineKeyboardButton("📦 تثبيت المتطلبات", callback_data=f"install_req_{actual_bot_name}")])
        
        keyboard.append([InlineKeyboardButton("📋 عرض المتطلبات", callback_data=f"view_req_{actual_bot_name}")])
        keyboard.append([InlineKeyboardButton("✏️ تعديل المتطلبات", callback_data=f"edit_req_{actual_bot_name}")])
    else:
        keyboard.append([InlineKeyboardButton("📝 إنشاء ملف متطلبات", callback_data=f"create_req_{actual_bot_name}")])
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

    elif data.startswith("create_req_"):
        bot_name = data[11:]
        await create_requirements_file(update, context, bot_name)

    elif data.startswith("upload_req_"):
        bot_name = data[11:]
        context.user_data['uploading_req_to'] = bot_name
        await query.edit_message_text("📤 أرسل ملف requirements.txt:")
        return REQUIREMENTS_SETUP

    elif data.startswith("edit_req_"):
        bot_name = data[9:]
        context.user_data['editing_req_to'] = bot_name
        await query.edit_message_text("📝 أرسل المحتوى الجديد لملف المتطلبات:")
        return REQUIREMENTS_SETUP

    return LIBRARY_MANAGEMENT

async def create_requirements_file(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """إنشاء ملف متطلبات تلقائياً"""
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
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')

    try:
        # إنشاء محتوى المتطلبات الافتراضي
        requirements_content = """python-telegram-bot
requests
aiohttp
psutil
pycryptodome
protobuf
Werkzeug"""

        # إنشاء المجلد إذا لم يكن موجوداً
        os.makedirs(bot_info['lib_folder'], exist_ok=True)

        with open(requirements_file, 'w', encoding='utf-8') as f:
            f.write(requirements_content)

        bot_info['has_requirements'] = True
        bot_info['requirements_installed'] = False
        save_data()

        keyboard = [
            [InlineKeyboardButton("🚀 تثبيت المتطلبات الآن", callback_data=f"install_req_{actual_bot_name}")],
            [InlineKeyboardButton("📋 عرض المتطلبات", callback_data=f"view_req_{actual_bot_name}")],
            [InlineKeyboardButton("✏️ تعديل المتطلبات", callback_data=f"edit_req_{actual_bot_name}")],
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"lib_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"✅ تم إنشاء ملف المتطلبات للبوت {actual_bot_name} بنجاح!\n\n"
            "📋 المتطلبات الافتراضية:\n"
            "• python-telegram-bot\n• requests\n• aiohttp\n• psutil\n"
            "• pycryptodome\n• protobuf\n• Werkzeug\n\n"
            "يمكنك الآن تثبيت المتطلبات أو تعديلها.",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ فشل في إنشاء ملف المتطلبات: {str(e)}")

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

    # حذف ملف المتطلبات
    requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')
    if os.path.exists(requirements_file):
        try:
            os.remove(requirements_file)
        except Exception as e:
            logger.error(f"خطأ في حذف ملف المتطلبات: {e}")

    bot_info['has_requirements'] = False
    bot_info['requirements_installed'] = False
    save_data()

    await query.edit_message_text(f"✅ تم حذف ملف المتطلبات للبوت {actual_bot_name}")

async def handle_requirements_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدخال المتطلبات"""
    user_id = update.effective_user.id
    message_text = update.message.text

    load_data()

    # التحقق من وجود البوت
    bot_name = context.user_data.get('adding_req_to') or context.user_data.get('editing_req_to')
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
        # إنشاء مجلد المكتبات إذا لم يكن موجوداً
        os.makedirs(bot_info['lib_folder'], exist_ok=True)

        # حفظ المحتوى في ملف المتطلبات
        with open(requirements_file, 'w', encoding='utf-8') as f:
            f.write(message_text)

        bot_info['has_requirements'] = True
        bot_info['requirements_installed'] = False
        save_data()

        # تحليل المتطلبات وحساب العدد
        lines = message_text.strip().split('\n')
        valid_requirements = [line for line in lines if line.strip() and not line.startswith('#')]

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
    """معالجة جميع الأزرار بما فيها الميزات الجديدة"""
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

    elif data.startswith("file_manager_"):
        bot_name = data[13:]
        await list_bot_files(update, context, bot_name)

    elif data.startswith("download_file_"):
        bot_name = data[14:]
        await download_bot_file(update, context, bot_name)

    elif data.startswith("delete_file_"):
        bot_name = data[12:]
        await delete_bot_file(update, context, bot_name)

    elif data.startswith("show_all_files_"):
        bot_name = data[15:]
        await show_all_bot_files(update, context, bot_name)

    elif data.startswith("dl_"):
        await handle_file_download(update, context)

    elif data.startswith("del_"):
        await handle_file_delete(update, context)

    # أزرار تنظيف السجلات
    elif data.startswith("clean_logs_"):
        bot_name = data[11:]
        await clean_bot_logs(update, context, bot_name)

    elif data.startswith("log_stats_"):
        bot_name = data[10:]
        await show_logs_statistics(update, context, bot_name)

    # أزرار وحدة التحكم
    elif data.startswith("term_"):
        await execute_terminal_command(update, context)

    elif data.startswith("cmd_"):
        await execute_terminal_command(update, context)

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
    """عرض رسالة المساعدة المحدثة"""
    help_text = """
🆘 **المساعدة المتقدمة - بوت إدارة البوتات**

📋 **الأوامر المتاحة:**

📤 **رفع ملف/مشروع** - رفع بوتات بايثون فردية أو مشاريع مضغوطة
🤖 **إدارة البوتات** - عرض وإدارة جميع البوتات الخاصة بك
⚙️ **الإعدادات العامة** - ضبط إعدادات النظام العامة
📊 **إحصائيات النظام** - عرض إحصائيات أداء النظام
🛠️ **إدارة المكتبات** - إدارة مكتبات ومتطلبات البوتات
❌ **إيقاف الجميع** - إوقف جميع البوتات النشطة
🧹 **تنظيف السجلات** - مسح سجلات البوتات وحفظ نسخ احتياطية
🖥️ **وحدة التحكم** - التحكم الكامل في الاستضافة عبر الأوامر
🌐 **استيراد من GitHub** - استيراد مشاريع مباشرة من GitHub
📦 **إدارة الحزم** - إدارة حزم ومكتبات النظام

🔧 **ميزات متقدمة:**
- تشغيل متعدد للبوتات
- إعادة تشغيل تلقائي
- بيئات افتراضية منعزلة
- إدارة المتطلبات التلقائية
- مراقبة الأداء
- سجلات مفصلة
- نظام حماية متقدم
- 🆕 تنظيف السجلات التلقائي
- 🆕 تحكم كامل في الاستضافة

💡 **أوامر وحدة التحكم:**
• `/terminal` - فتح وحدة التحكم
• `ls, cd, pwd` - التنقل بين الملفات
• `python, pip` - إدارة بايثون
• `top, ps, df` - مراقبة النظام
• أوامر مخصصة بأي لغة

⚠️ **تحذيرات الأمان:**
- وحدة التحكم تنفذ الأوامر بكامل الصلاحيات
- استخدمها بحذر شديد
- احتفظ بنسخ احتياطية من الملفات المهمة

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

# ======= الأوامر الجديدة لحل مشاكل المتطلبات ======= #
async def fix_requirements_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إصلاح مشاكل المتطلبات تلقائياً"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ هذا الأمر متاح للمشرف فقط")
        return

    await update.message.reply_text("🔧 جاري فحص وإصلاح مشاكل المتطلبات...")

    load_data()

    fixed_count = 0
    total_bots = 0

    for user_id, user_data in user_bots.items():
        for bot_name, bot_info in user_data['bots'].items():
            total_bots += 1
            requirements_file = os.path.join(bot_info['lib_folder'], 'requirements.txt')
            
            # إصلاح البوت app_608
            if user_id == 7883114406 and "app_608" in bot_name:
                try:
                    # إنشاء مجلد المكتبات إذا لم يكن موجوداً
                    os.makedirs(bot_info['lib_folder'], exist_ok=True)
                    
                    # إنشاء ملف المتطلبات
                    requirements_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
                    
                    with open(requirements_file, 'w', encoding='utf-8') as f:
                        f.write(requirements_content)
                    
                    bot_info['has_requirements'] = True
                    fixed_count += 1
                    logger.info(f"تم إصلاح متطلبات البوت {bot_name} للمستخدم {user_id}")
                    
                except Exception as e:
                    logger.error(f"فشل إصلاح البوت {bot_name}: {e}")

    save_data()
    
    await update.message.reply_text(
        f"✅ تم الانتهاء من الفحص والإصلاح:\n"
        f"• تم فحص {total_bots} بوت\n"
        f"• تم إصلاح {fixed_count} بوت\n"
        f"• البوت app_608 جاهز الآن لتثبيت المتطلبات"
    )

async def system_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض حالة النظام المفصلة"""
    user_id = update.effective_user.id
    
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ هذا الأمر متاح للمشرف فقط")
        return

    # معلومات النظام
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # معلومات البوتات
    total_bots = 0
    running_bots = 0
    bots_with_requirements = 0
    bots_installed = 0
    
    for user_data in user_bots.values():
        total_bots += len(user_data['bots'])
        for bot_info in user_data['bots'].values():
            if bot_info['status'] == 'running':
                running_bots += 1
            if bot_info.get('has_requirements', False):
                bots_with_requirements += 1
            if bot_info.get('requirements_installed', False):
                bots_installed += 1

    status_text = f"""
🖥️ **حالة النظام المفصلة**

📊 **أداء النظام:**
• استخدام المعالج: {cpu_percent}%
• استخدام الذاكرة: {memory.percent}% ({memory.used // 1024 // 1024}MB / {memory.total // 1024 // 1024}MB)
• استخدام التخزين: {disk.percent}% ({disk.used // 1024 // 1024 // 1024}GB / {disk.total // 1024 // 1024 // 1024}GB)

🤖 **إحصائيات البوتات:**
• إجمالي البوتات: {total_bots}
• البوتات النشطة: {running_bots}
• البوتات المتوقفة: {total_bots - running_bots}
• البوتات بملفات متطلبات: {bots_with_requirements}
• البوتات بمتطلبات مثبتة: {bots_installed}

🔧 **معلومات التشغيل:**
• نظام الحماية: {'مفعل ✅' if protection_enabled else 'معطل ❌'}
• مستوى الحماية: {protection_level}
• عدد المستخدمين: {len(user_bots)}
• المهام النشطة: {sum(len(tasks) for tasks in restart_tasks.values())}
"""

    await update.message.reply_text(status_text, parse_mode='HTML')

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
                    CallbackQueryHandler(handle_button_callback, pattern="^(run_|install_|settings_|delete_|file_manager_|download_file_|delete_file_|show_all_files_|dl_|del_|cancel_)")],
                BOT_MANAGEMENT: [
                    CallbackQueryHandler(handle_bot_management, pattern="^(manage_|add_new_bot|back_to_)")],
                LIBRARY_MANAGEMENT: [CallbackQueryHandler(handle_library_management,
                                                          pattern="^(lib_|install_|create_|upload_|view_|edit_|back_to_)")],
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
        application.add_handler(CommandHandler("fix_requirements", fix_requirements_command))
        application.add_handler(CommandHandler("system_status", system_status_command))
        application.add_handler(MessageHandler(filters.Regex("^(❌ إيقاف الجميع)$"), stop_all_bots))
        application.add_handler(MessageHandler(filters.Regex("^(📊 إحصائيات النظام)$"), show_statistics))
        application.add_handler(MessageHandler(filters.Regex("^(🆘 المساعدة المتقدمة)$"), help_command))
        application.add_handler(CallbackQueryHandler(handle_button_callback))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_env_input))
        application.add_handler(CommandHandler("fix_req", fix_requirements_now))
        application.add_handler(CommandHandler("terminal", terminal_control))
        application.add_handler(CommandHandler("clean_logs", clean_all_logs))
        application.add_handler(MessageHandler(filters.Regex("^(🧹 تنظيف السجلات)$"), clean_all_logs))
        application.add_handler(MessageHandler(filters.Regex("^(🖥️ وحدة التحكم)$"), terminal_control))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_custom_command))





        # إضافة معالج الأخطاء
        application.add_error_handler(error_handler)

        logger.info("🤖 بدء تشغيل بوت إدارة البوتات المحسّن...")
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
