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
protection_level = "medium"
suspicious_files_dir = 'suspicious_files'
MAX_FILE_SIZE = 5 * 1024 * 1024

# إنشاء مجلد الملفات المشبوهة
if not os.path.exists(suspicious_files_dir):
    os.makedirs(suspicious_files_dir)

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

# ======= نظام تثبيت المتطلبات المحسّن النهائي ======= #
async def install_requirements_real_time(requirements_file, bot_lib_folder, user_id, chat_id, bot_name, bot_instance, bot_info):
    """تثبيت المتطلبات حقيقياً مع عرض التقدم في الوقت الحقيقي - الإصدار النهائي المحسّن"""
    try:
        # إرسال رسالة بدء التثبيت
        status_message = await bot_instance.send_message(
            chat_id, 
            f"📦 جاري تثبيت متطلبات البوت {bot_name}...\n⏳ قد تستغرق هذه العملية عدة دقائق"
        )
        
        # التحقق من وجود ملف المتطلبات وإنشاؤه إذا لزم الأمر
        logger.info(f"🔍 البحث عن ملف المتطلبات في: {requirements_file}")
        logger.info(f"📁 المجلد: {bot_lib_folder}")
        
        # التأكد من وجود المجلد
        if not os.path.exists(bot_lib_folder):
            logger.info(f"📁 إنشاء المجلد: {bot_lib_folder}")
            os.makedirs(bot_lib_folder, exist_ok=True)
        
        # إذا لم يكن الملف موجوداً، قم بإنشائه تلقائياً
        if not os.path.exists(requirements_file):
            logger.warning(f"❌ ملف المتطلبات غير موجود: {requirements_file}")
            
            # إنشاء ملف متطلبات افتراضي
            requirements_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
            
            logger.info(f"📝 إنشاء ملف متطلبات تلقائي للبوت {bot_name}")
            with open(requirements_file, 'w', encoding='utf-8') as f:
                f.write(requirements_content)
            
            await status_message.edit_text("✅ تم إنشاء ملف المتطلبات تلقائياً")
        
        # التحقق من أن الملف موجود الآن
        if not os.path.exists(requirements_file):
            await status_message.edit_text("❌ فشل في إنشاء ملف المتطلبات")
            return False, "فشل في إنشاء ملف المتطلبات"

        # قراءة المتطلبات أولاً لعرضها
        try:
            with open(requirements_file, 'r', encoding='utf-8') as f:
                requirements_content = f.read().strip()
                requirements_list = [line for line in requirements_content.split('\n') if line.strip() and not line.startswith('#')]
            
            requirements_count = len(requirements_list)
            if requirements_count > 0:
                await status_message.edit_text(f"🚀 بدء تثبيت {requirements_count} مكتبة...\n\n📋 قائمة المكتبات:\n" + "\n".join(requirements_list[:10]) + ("\n..." if len(requirements_list) > 10 else ""))
            else:
                await status_message.edit_text("⚠️ ملف المتطلبات فارغ أو لا يحتوي على مكتبات صالحة")
                return False, "ملف المتطلبات فارغ"
        except Exception as e:
            await status_message.edit_text(f"⚠️ خطأ في قراءة ملف المتطلبات: {str(e)}")
            return False, f"خطأ في قراءة ملف المتطلبات: {str(e)}"

        # تثبيت المتطلبات مع التقدم في الوقت الحقيقي
        await status_message.edit_text(f"🔧 جاري تثبيت {requirements_count} مكتبة...")

        try:
            # استخدام pip مباشرة مع تحسينات
            process = subprocess.Popen(
                [sys.executable, '-m', 'pip', 'install', '-r', requirements_file, '--no-cache-dir'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=bot_lib_folder
            )

            # قراءة المخرجات في الوقت الحقيقي
            output_lines = []
            
            def read_output(stream, lines):
                for line in iter(stream.readline, ''):
                    if line.strip():
                        lines.append(line.strip())
            
            # قراءة stdout و stderr في خيوط منفصلة
            stdout_thread = threading.Thread(target=read_output, args=(process.stdout, output_lines))
            stderr_thread = threading.Thread(target=read_output, args=(process.stderr, output_lines))
            
            stdout_thread.start()
            stderr_thread.start()

            # الانتظار حتى انتهاء العملية مع تحديث التقدم
            last_update = time.time()
            while process.poll() is None:
                time.sleep(1)
                # تحديث التقدم كل 10 ثواني
                if time.time() - last_update > 10:
                    progress_text = f"🔧 جاري التثبيت...\nتم معالجة {len(output_lines)} سطر\nآخر تحديث: {datetime.now().strftime('%H:%M:%S')}"
                    try:
                        await status_message.edit_text(progress_text)
                    except:
                        pass
                    last_update = time.time()

            # الانتظار حتى انتهاء خيوط القراءة
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)

            if process.returncode == 0:
                # تحليل المخرجات لاستخراج المكتبات المثبتة
                installed_packages = []
                for line in output_lines:
                    if 'Successfully installed' in line:
                        parts = line.split('Successfully installed')[-1].strip()
                        installed_packages.extend([pkg.strip() for pkg in parts.split() if pkg.strip()])
                
                success_message = f"✅ تم تثبيت متطلبات {bot_name} بنجاح!\n\n"
                if installed_packages:
                    success_message += f"📊 تم تثبيت {len(installed_packages)} مكتبة:\n"
                    success_message += ", ".join(installed_packages[:15])
                    if len(installed_packages) > 15:
                        success_message += f"\n... و {len(installed_packages) - 15} مكتبة أخرى"
                success_message += "\n\n🎉 البوت جاهز للتشغيل!"
                
                await status_message.edit_text(success_message)
                return True, "\n".join(output_lines[-20:])
            else:
                # معالجة الأخطاء
                error_output = "\n".join(output_lines[-10:])
                error_message = f"❌ فشل تثبيت متطلبات {bot_name}:\n\n{error_output}"
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
            await bot_instance.send_message(chat_id, error_msg)
        except:
            pass
        return False, error_msg

async def install_requirements_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_name: str):
    """معالجة تثبيت متطلبات البوت مع التقدم المرئي - الإصدار النهائي"""
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
    
    # التأكد من وجود مجلد المكتبات
    lib_folder = bot_info.get('lib_folder', '')
    if not lib_folder:
        # إنشاء مسار افتراضي إذا لم يكن موجوداً
        lib_folder = os.path.join(LIBRARY_FOLDER, f"{user_id}_{actual_bot_name}")
        bot_info['lib_folder'] = lib_folder
        save_data()
    
    # التأكد من وجود المجلد
    if not os.path.exists(lib_folder):
        os.makedirs(lib_folder, exist_ok=True)
        logger.info(f"📁 تم إنشاء مجلد المكتبات: {lib_folder}")

    requirements_file = os.path.join(lib_folder, 'requirements.txt')

    # بدء عملية التثبيت الحقيقية
    await query.edit_message_text(f"🚀 بدء عملية تثبيت المتطلبات للبوت {actual_bot_name}...")

    # استخدام asyncio.create_task للتشغيل غير المتزامن
    asyncio.create_task(
        run_installation_process(requirements_file, lib_folder, user_id, chat_id, actual_bot_name, context.bot, bot_info)
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
            bot_instance,
            bot_info
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

    # إذا لم يكن الملف موجوداً، قم بإنشائه تلقائياً
    if not os.path.exists(requirements_file):
        # إنشاء ملف متطلبات افتراضي
        requirements_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
pycryptodome
protobuf
Werkzeug"""
        
        os.makedirs(bot_info['lib_folder'], exist_ok=True)
        with open(requirements_file, 'w', encoding='utf-8') as f:
            f.write(requirements_content)
        
        bot_info['has_requirements'] = True
        save_data()

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

# ======= دوال الحماية ======= #
def is_admin(user_id):
    return user_id == ADMIN_ID

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

        # أنماط الحماية الأساسية
        patterns = [
            r"rm\s+-rf\s+[\'\"]?/",
            r"dd\s+if=\S+\s+of=\S+",
            r":\(\)\{\s*:\|\:\s*\&\s*\};:",
            r"chmod\s+-R\s+777\s+[\'\"]?/",
        ]

        threat_type = ""

        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                suspicious_code = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                activity = f"تم اكتشاف أمر خطير: {match.group(0)} في السياق: {suspicious_code}"
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

def log_suspicious_activity(user_id, activity, file_name=None):
    """دالة لتسجيل النشاط المشبوه"""
    try:
        banned_users.add(user_id)
        logging.warning(f"تم حظر المستخدم {user_id} بسبب نشاط مشبوه: {activity}")
    except Exception as e:
        logging.error(f"فشل في تسجيل النشاط المشبوه: {e}")

# ======= نظام التشغيل التلقائي ======= #
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

                auto_start = bot_info.get('auto_start', False)
                status = bot_info.get('status', 'stopped')
                pid = bot_info.get('pid')

                logger.info(f"فحص البوت {bot_name}: auto_start={auto_start}, status={status}, pid={pid}")

                process_running = check_process_running(pid)

                if status == 'running' and not process_running:
                    logger.warning(f"البوت {bot_name} مسجل كقيد التشغيل ولكن العملية غير نشطة.")
                    bot_info['status'] = 'stopped'
                    save_data()

                if auto_start and bot_info['status'] == 'stopped':
                    logger.info(f"محاولة تشغيل البوت التلقائي: {bot_name}")
                    if start_bot_auto(user_id, bot_name, bot_info):
                        started_bots += 1
                        logger.info(f"تم التشغيل التلقائي للبوت: {bot_name} للمستخدم: {user_id}")
                    else:
                        logger.error(f"فشل التشغيل التلقائي للبوت: {bot_name} للمستخدم: {user_id}")

        except Exception as e:
            logger.error(f"خطأ في التشغيل التلقائي لبوتات المستخدم {user_id}: {e}")
            continue

    logger.info(f"اكتمل التشغيل التلقائي: {started_bots}/{total_bots} بوت تم تشغيله")

def start_bot_auto(user_id, bot_name, bot_info):
    """تشغيل البوت تلقائياً مع تحسينات"""
    try:
        file_path = bot_info['file_path']

        if not os.path.exists(file_path):
            logger.error(f"ملف البوت غير موجود: {file_path}")
            bot_info['status'] = 'stopped'
            save_data()
            return False

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

        process_key = f"{user_id}_{bot_name}"
        bot_processes[process_key] = process

        bot_info['status'] = 'running'
        bot_info['last_start'] = datetime.now().isoformat()
        bot_info['pid'] = process.pid

        if bot_info.get('auto_restart', False):
            if user_id not in restart_tasks:
                restart_tasks[user_id] = {}

            restart_tasks[user_id][bot_name] = {
                'interval': bot_info.get('restart_interval', 60),
                'max_restarts': bot_info.get('max_restarts', 10),
                'restarts': 0
            }

            monitor_thread = threading.Thread(
                target=monitor_bot,
                args=(user_id, bot_name, user_id, None),
                daemon=True
            )
            monitor_thread.start()

        save_data()

        logger.info(f"تم تشغيل البوت {bot_name} بنجاح - PID: {process.pid}")
        return True

    except Exception as e:
        logger.error(f"فشل التشغيل التلقائي للبوت {bot_name}: {str(e)}")
        bot_info['status'] = 'stopped'
        save_data()
        return False

def monitor_bot(user_id, bot_name, chat_id, bot_instance):
    """مراقبة البوت وإعادة تشغيله تلقائياً"""
    logger.info(f"بدء مراقبة البوت: {bot_name} للمستخدم: {user_id}")

    while True:
        process_key = f"{user_id}_{bot_name}"

        if (user_id not in restart_tasks or
                bot_name not in restart_tasks[user_id] or
                process_key not in bot_processes):
            logger.info(f"توقف مراقبة البوت: {bot_name}")
            break

        process = bot_processes[process_key]

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue

        if (user_id not in restart_tasks or
                bot_name not in restart_tasks[user_id] or
                process_key not in bot_processes):
            break

        if process.poll() is not None:
            current_restarts = restart_tasks[user_id][bot_name]['restarts']
            max_restarts = restart_tasks[user_id][bot_name]['max_restarts']

            if current_restarts < max_restarts:
                logger.info(f"إعادة تشغيل البوت {bot_name} (المحاولة {current_restarts + 1})")

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

# ======= دوال إدارة المكتبات ======= #
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
        requirements_content = """Flask[async]
requests
aiohttp
googleapis-common-protos
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
            [InlineKeyboardButton("🔙 رجوع", callback_data=f"lib_{actual_bot_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"✅ تم إنشاء ملف المتطلبات للبوت {actual_bot_name} بنجاح!\n\n"
            "📋 المتطلبات الافتراضية:\n"
            "• Flask[async]\n• requests\n• aiohttp\n• googleapis-common-protos\n"
            "• pycryptodome\n• protobuf\n• Werkzeug\n\n"
            "يمكنك الآن تثبيت المتطلبات.",
            reply_markup=reply_markup
        )

    except Exception as e:
        await query.edit_message_text(f"❌ فشل في إنشاء ملف المتطلبات: {str(e)}")

async def handle_requirements_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة إدخال المتطلبات"""
    user_id = update.effective_user.id
    message_text = update.message.text

    load_data()

    # التحقق من وجود البوت
    bot_name = context.user_data.get('adding_req_to')
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

يمكنك الآن تثبيت المتطلبات.
"""

        await update.message.reply_text(success_message, reply_markup=reply_markup)

    except Exception as e:
        error_message = f"❌ حدث خطأ أثناء حفظ الملف: {str(e)}"
        await update.message.reply_text(error_message)

    return ConversationHandler.END

# ======= handlers المحادثة الأساسية ======= #
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
        [KeyboardButton("🛠️ إدارة المكتبات"), KeyboardButton("❌ إيقاف الجميع")],
        [KeyboardButton("🆘 المساعدة"), KeyboardButton("📊 إحصائيات النظام")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        "🚀 مرحباً! أنا البوت المتقدم المتكامل لإدارة وتشغيل بوتات تيليجرام.\n\n"
        "اختر أحد الخيارات المتاحة:",
        reply_markup=reply_markup
    )

async def upload_option(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض خيارات الرفع"""
    keyboard = [
        [InlineKeyboardButton("📄 ملف بايثون فردي", callback_data="upload_python")],
        [InlineKeyboardButton("📦 ملف مضغوط (ZIP/TAR)", callback_data="upload_zip")],
        [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_upload")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "اختر طريقة رفع البوت:",
        reply_markup=reply_markup
    )
    return UPLOAD

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
            [InlineKeyboardButton("⚙️ الإعدادات", callback_data=f"settings_{bot_name}")],
            [InlineKeyboardButton("❌ حذف", callback_data=f"delete_{bot_name}")]
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

async def handle_button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة جميع الأزرار"""
    query = update.callback_query

    if query is None:
        return

    await query.answer()

    if query.message is None:
        return

    user_id = query.from_user.id
    data = query.data

    if data.startswith("install_req_"):
        bot_name = data[12:]
        await install_requirements_handler(update, context, bot_name)

    elif data.startswith("view_req_"):
        bot_name = data[9:]
        await view_requirements_detailed(update, context, bot_name)

    elif data.startswith("lib_"):
        bot_name = data[4:]
        await show_library_options(update, context, bot_name)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض رسالة المساعدة"""
    help_text = """
🆘 **المساعدة - بوت إدارة البوتات**

📋 **الأوامر المتاحة:**

📤 **رفع ملف/مشروع** - رفع بوتات بايثون فردية
🤖 **إدارة البوتات** - عرض وإدارة جميع البوتات
🛠️ **إدارة المكتبات** - إدارة مكتبات ومتطلبات البوتات
❌ **إيقاف الجميع** - إوقف جميع البوتات النشطة
📊 **إحصائيات النظام** - عرض إحصائيات أداء النظام

🔧 **ميزات متقدمة:**
- تشغيل متعدد للبوتات
- إعادة تشغيل تلقائي
- إدارة المتطلبات التلقائية
- مراقبة الأداء
- نظام حماية متقدم

💡 **نصائح:**
- تأكد من وجود ملف `requirements.txt` للمشاريع الكبيرة
- استخدم إدارة المكتبات لتثبيت المتطلبات
- راقب استخدام الذاكرة والمسؤولية
    """

    await update.message.reply_text(help_text, parse_mode='HTML')

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
• استخدام الذاكرة: {memory.percent}%
• استخدام التخزين: {disk.percent}%

🤖 **إحصائيات البوتات:**
• إجمالي البوتات: {total_bots}
• البوتات النشطة: {running_bots}
• البوتات المتوقفة: {total_bots - running_bots}
• إجمالي عمليات إعادة التشغيل: {total_restarts}

🔧 **معلومات التشغيل:**
• نظام الحماية: {'مفعل ✅' if protection_enabled else 'معطل ❌'}
• عدد المستخدمين: {len(user_bots)}
    """

    await update.message.reply_text(stats_text, parse_mode='HTML')

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

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إلغاء المحادثة"""
    await update.message.reply_text("✅ تم إلغاء العملية الحالية.")
    return ConversationHandler.END

# ======= الأوامر الإدارية ======= #
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
            
            # التأكد من وجود مجلد المكتبات
            lib_folder = bot_info.get('lib_folder', '')
            if not lib_folder:
                lib_folder = os.path.join(LIBRARY_FOLDER, f"{user_id}_{bot_name}")
                bot_info['lib_folder'] = lib_folder
            
            # التأكد من وجود المجلد
            if not os.path.exists(lib_folder):
                os.makedirs(lib_folder, exist_ok=True)

            requirements_file = os.path.join(lib_folder, 'requirements.txt')
            
            # إنشاء ملف المتطلبات إذا لم يكن موجوداً
            if not os.path.exists(requirements_file):
                try:
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
                    logger.info(f"✅ تم إصلاح متطلبات البوت {bot_name}")
                    
                except Exception as e:
                    logger.error(f"❌ فشل إصلاح البوت {bot_name}: {e}")

    save_data()
    
    await update.message.reply_text(
        f"✅ تم الانتهاء من الفحص والإصلاح:\n"
        f"• تم فحص {total_bots} بوت\n"
        f"• تم إصلاح {fixed_count} بوت\n"
        f"• جميع البوتات جاهزة الآن لتثبيت المتطلبات"
    )

def main():
    """الدالة الرئيسية"""
    if not BOT_TOKEN:
        logger.error("❌ يرجى تعيين توكن البوت الصحيح")
        return

    try:
        application = Application.builder().token(BOT_TOKEN).build()

        conv_handler = ConversationHandler(
            entry_points=[
                MessageHandler(filters.Regex("^(📤 رفع ملف/مشروع)$"), upload_option),
                MessageHandler(filters.Regex("^(🛠️ إدارة المكتبات)$"), library_management),
            ],
            states={
                UPLOAD: [
                    MessageHandler(filters.Document.ALL, handle_document),
                ],
                LIBRARY_MANAGEMENT: [CallbackQueryHandler(handle_library_management)],
                REQUIREMENTS_SETUP: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, handle_requirements_input),
                    MessageHandler(filters.Document.ALL, handle_requirements_upload)
                ],
            },
            fallbacks=[CommandHandler('cancel', cancel)]
        )

        application.add_handler(conv_handler)
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("stop_all", stop_all_bots))
        application.add_handler(CommandHandler("fix_requirements", fix_requirements_command))
        application.add_handler(MessageHandler(filters.Regex("^(❌ إيقاف الجميع)$"), stop_all_bots))
        application.add_handler(MessageHandler(filters.Regex("^(📊 إحصائيات النظام)$"), show_statistics))
        application.add_handler(MessageHandler(filters.Regex("^(🆘 المساعدة)$"), help_command))
        application.add_handler(CallbackQueryHandler(handle_button_callback))

        logger.info("🤖 بدء تشغيل بوت إدارة البوتات المحسّن...")
        print("🤖 البوت يعمل الآن! استخدم /start للبدء")

        # تشغيل البوتات التلقائي عند بدء التشغيل
        auto_start_all_bots_on_load()

        application.run_polling(drop_pending_updates=True)

    except Exception as e:
        logger.error(f"❌ فشل تشغيل البوت: {e}")
        print(f"❌ فشل تشغيل البوت: {e}")

if __name__ == '__main__':
    main()
