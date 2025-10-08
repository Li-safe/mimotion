# -*- coding: utf8 -*-
import math
import traceback
from datetime import datetime
import pytz
import uuid

import json
import random
import re
import time
import os
import logging

import requests
from util.aes_help import  encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mimotion.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 获取默认值转int
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))


# 验证配置完整性
def validate_config(config):
    """验证配置的完整性和有效性"""
    required_fields = ['USER', 'PWD']
    missing_fields = [field for field in required_fields if not config.get(field)]
    
    if missing_fields:
        logger.error(f"缺少必要配置字段: {missing_fields}")
        return False
    
    # 验证账号密码数量匹配
    users = config.get('USER', '').split('#')
    passwords = config.get('PWD', '').split('#')
    
    if len(users) != len(passwords):
        logger.error(f"账号数量({len(users)})与密码数量({len(passwords)})不匹配")
        return False
    
    # 验证步数范围
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    
    if min_step >= max_step:
        logger.error(f"最小步数({min_step})不能大于等于最大步数({max_step})")
        return False
    
    if min_step < 0 or max_step < 0:
        logger.error("步数不能为负数")
        return False
    
    logger.info("配置验证通过")
    return True


# 获取当前时间对应的最大和最小步数
def get_min_max_by_time(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    return int(time_rate * min_step), int(time_rate * max_step)


# 虚拟ip地址
def fake_ip():
    # 随便找的国内IP段：223.64.0.0 - 223.117.255.255
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


# 账号脱敏
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'


# 获取北京时间
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    # 获取当前时间
    return datetime.now().astimezone(target_timezone)


# 格式化时间
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


# 获取时间戳
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)


# 获取登录code
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


# pushplus消息推送
def push_plus(title, content):
    requestUrl = f"http://www.pushplus.plus/send"
    data = {
        "token": PUSH_PLUS_TOKEN,
        "title": title,
        "content": content,
        "template": "html",
        "channel": "wechat"
    }
    try:
        response = requests.post(requestUrl, data=data)
        if response.status_code == 200:
            json_res = response.json()
            print(f"pushplus推送完毕：{json_res['code']}-{json_res['msg']}")
        else:
            print("pushplus推送失败")
    except:
        print("pushplus推送异常")


class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None
        self.device_id = str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            pass
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user
        if user.startswith("+86"):
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user
        # self.fake_ip_addr = fake_ip()
        # self.log_str += f"创建虚拟ip地址：{self.fake_ip_addr}\n"

    # 登录
    def login(self):
        user_token_info = user_tokens.get(self.user)
        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")
            self.user_id = user_token_info.get("user_id")
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id
            ok,msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token
            else:
                self.log_str += f"app_token失效 重新获取 last grant time: {user_token_info.get('app_token_time')}\n"
                # 检查login_token是否可用
                app_token, msg = zeppHelper.grant_app_token(login_token)
                if app_token is None:
                    self.log_str += f"login_token 失效 重新获取 last grant time: {user_token_info.get('login_token_time')}\n"
                    login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id, self.is_phone)
                    if login_token is None:
                        self.log_str += f"access_token 已失效：{msg} last grant time:{user_token_info.get('access_token_time')}\n"
                    else:
                        user_token_info["login_token"] = login_token
                        user_token_info["app_token"] = app_token
                        user_token_info["user_id"] = user_id
                        user_token_info["login_token_time"] = get_time()
                        user_token_info["app_token_time"] = get_time()
                        self.user_id = user_id
                        return app_token
                else:
                    self.log_str += "重新获取app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token

        # access_token 失效 或者没有保存加密数据
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "登录获取accessToken失败：%s" % msg
            return None
        # print(f"device_id:{self.device_id} isPhone: {self.is_phone}")
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id, self.is_phone)
        if login_token is None:
            self.log_str += f"登录提取的 access_token 无效：{msg}"
            return None

        user_token_info = dict()
        user_token_info["access_token"] = access_token
        user_token_info["login_token"] = login_token
        user_token_info["app_token"] = app_token
        user_token_info["user_id"] = user_id
        # 记录token获取时间
        user_token_info["access_token_time"] = get_time()
        user_token_info["login_token_time"] = get_time()
        user_token_info["app_token_time"] = get_time()
        if self.device_id is None:
            self.device_id = uuid.uuid4()
        user_token_info["device_id"] = self.device_id
        user_tokens[self.user] = user_token_info
        return app_token


    # 主函数
    def login_and_post_step(self, min_step, max_step):
        if self.invalid:
            return "账号或密码配置有误", False
        app_token = self.login()
        if app_token is None:
            return "登陆失败！", False

        step = str(random.randint(min_step, max_step))
        self.log_str += f"已设置为随机步数范围({min_step}~{max_step}) 随机值:{step}\n"
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数（{step}）[" + msg + "]", ok


# 启动主函数
def push_to_push_plus(exec_results, summary):
    # 判断是否需要pushplus推送
    if PUSH_PLUS_TOKEN is not None and PUSH_PLUS_TOKEN != '' and PUSH_PLUS_TOKEN != 'NO':
        if PUSH_PLUS_HOUR is not None and PUSH_PLUS_HOUR.isdigit():
            if time_bj.hour != int(PUSH_PLUS_HOUR):
                print(f"当前设置push_plus推送整点为：{PUSH_PLUS_HOUR}, 当前整点为：{time_bj.hour}，跳过推送")
                return
        html = f'<div>{summary}</div>'
        if len(exec_results) >= PUSH_PLUS_MAX:
            html += '<div>账号数量过多，详细情况请前往github actions中查看</div>'
        else:
            html += '<ul>'
            for exec_result in exec_results:
                success = exec_result['success']
                if success is not None and success is True:
                    html += f'<li><span>账号：{exec_result["user"]}</span>刷步数成功，接口返回：{exec_result["msg"]}</li>'
                else:
                    html += f'<li><span>账号：{exec_result["user"]}</span>刷步数失败，失败原因：{exec_result["msg"]}</li>'
            html += '</ul>'
        push_plus(f"{format_now()} 刷步数通知", html)


def run_single_account(total, idx, user_mi, passwd_mi, max_retries=3):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    
    for attempt in range(max_retries):
        try:
            runner = MiMotionRunner(user_mi, passwd_mi)
            exec_msg, success = runner.login_and_post_step(min_step, max_step)
            log_str += runner.log_str
            log_str += f'{exec_msg}\n'
            exec_result = {"user": user_mi, "success": success,
                           "msg": exec_msg}
            break
        except Exception as e:
            if attempt < max_retries - 1:
                log_str += f"第{attempt + 1}次尝试失败，{max_retries - attempt - 1}次重试机会: {str(e)}\n"
                time.sleep(2)  # 重试前等待2秒
            else:
                log_str += f"执行异常（已重试{max_retries}次）:{traceback.format_exc()}\n"
                exec_result = {"user": user_mi, "success": False,
                               "msg": f"执行异常（已重试{max_retries}次）:{str(e)}"}
    
    print(log_str)
    return exec_result


def execute():
    start_time = time.time()
    logger.info("开始执行刷步数任务")
    
    # --- 开始集成：分批处理逻辑 ---
    # 从环境变量中获取当前批次，如果不存在则默认为0
    current_batch = int(os.getenv('CURRENT_BATCH', 0))

    user_list = users.split('#')
    passwd_list = passwords.split('#')

    # 计算总批次数，每批9个账号
    batch_size = 9
    total_batches = math.ceil(len(user_list) / batch_size)

    # 如果当前批次号已超出总批次数，重置为0开始新的循环
    if current_batch >= total_batches:
        print("所有账号已执行完毕，重置批次号从头开始循环")
        current_batch = 0
        os.environ['CURRENT_BATCH'] = '0'  # 重置批次号

    # 计算当前批次的账号范围
    start_index = current_batch * batch_size
    end_index = min((current_batch + 1) * batch_size, len(user_list))
    
    # 切割出当前批次要处理的账号和密码列表
    batch_user_list = user_list[start_index:end_index]
    batch_passwd_list = passwd_list[start_index:end_index]
    # --- 分批处理逻辑集成结束 ---

    # --- 原有逻辑，但现在操作的是当前批次的列表 ---
    exec_results = []
    if len(batch_user_list) == len(batch_passwd_list):
        # 使用当前批次的数量作为总数
        idx, total = 0, len(batch_user_list) 
        
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # 将 lambda 函数应用于当前批次的账号
                exec_results = list(executor.map(lambda x: run_single_account(total, x[0], *x[1]),
                                                 enumerate(zip(batch_user_list, batch_passwd_list))))
        else:
            # 遍历当前批次的账号
            for user_mi, passwd_mi in zip(batch_user_list, batch_passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
                idx += 1
                if idx < total:
                    # 每个账号之间间隔一定时间请求一次，避免接口请求过于频繁导致异常
                    time.sleep(sleep_seconds)
        
        if encrypt_support:
            persist_user_tokens()
            
        success_count = sum(1 for result in exec_results if result['success'] is True)
        push_results = exec_results.copy()  # 直接复制，避免重复遍历
                
        # 计算执行时间
        execution_time = time.time() - start_time
        
        # 摘要信息也更新为当前批次的信息
        summary = f"\n执行账号总数{total}，成功：{success_count}，失败：{total - success_count}，耗时：{execution_time:.2f}秒"
        print(summary)
        logger.info(f"批次执行完成 - 成功：{success_count}，失败：{total - success_count}，耗时：{execution_time:.2f}秒")
        push_to_push_plus(push_results, summary)
        
        # --- 开始集成：批次完成后的更新逻辑 ---
        # 执行完成后更新当前批次号
        next_batch = current_batch + 1
        os.environ['CURRENT_BATCH'] = str(next_batch)  # 更新当前批次
        print(f"本批次执行完毕，已更新批次号至 {next_batch}，下次将从此批次开始。")
        # --- 批次更新逻辑集成结束 ---

    else:
        # 此处的错误提示也改为当前批次的信息
        print(f"当前批次账号数长度[{len(batch_user_list)}]和密码数长度[{len(batch_passwd_list)}]不匹配，跳过执行")
        exit(1)



def prepare_user_tokens() -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
            decrypted_data = decrypt_data(data, aes_key, None)
            # 假设原始明文为 UTF-8 编码文本
            return json.loads(decrypted_data.decode('utf-8', errors='strict'))
        except:
            print("密钥不正确或者加密内容损坏 放弃token")
            return dict()
    else:
        return dict()

def persist_user_tokens():
    data_path = r"encrypted_tokens.data"
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    with open(data_path, 'wb') as f:
        f.write(cipher_data)
        f.flush()
        f.close()

if __name__ == "__main__":
    # 北京时间
    time_bj = get_beijing_time()
    encrypt_support = False
    user_tokens = dict()
    if os.environ.__contains__("AES_KEY") is True:
        aes_key = os.environ.get("AES_KEY")
        if aes_key is not None:
            aes_key = aes_key.encode('utf-8')
            if len(aes_key) == 16:
                encrypt_support = True
        if encrypt_support:
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY未设置或者无效 无法使用加密保存功能")
    if os.environ.__contains__("CONFIG") is False:
        print("未配置CONFIG变量，无法执行")
        exit(1)
    else:
        # region 初始化参数
        config = dict()
        try:
            config = dict(json.loads(os.environ.get("CONFIG")))
        except json.JSONDecodeError as e:
            logger.error(f"CONFIG JSON格式错误: {e}")
            print("请检查Secret配置，严格按照JSON格式：使用双引号包裹字段和值，逗号不能多也不能少")
            exit(1)
        except Exception as e:
            logger.error(f"CONFIG解析异常: {e}")
            traceback.print_exc()
            exit(1)
        
        # 验证配置
        if not validate_config(config):
            logger.error("配置验证失败，程序退出")
            exit(1)
        PUSH_PLUS_TOKEN = config.get('PUSH_PLUS_TOKEN')
        PUSH_PLUS_HOUR = config.get('PUSH_PLUS_HOUR')
        PUSH_PLUS_MAX = get_int_value_default(config, 'PUSH_PLUS_MAX', 30)
        sleep_seconds = config.get('SLEEP_GAP')
        if sleep_seconds is None or sleep_seconds == '':
            sleep_seconds = 5
        sleep_seconds = float(sleep_seconds)
        users = config.get('USER')
        passwords = config.get('PWD')
        if users is None or passwords is None:
            print("未正确配置账号密码，无法执行")
            exit(1)
        min_step, max_step = get_min_max_by_time()
        use_concurrent = config.get('USE_CONCURRENT')
        if use_concurrent is not None and use_concurrent == 'True':
            use_concurrent = True
        else:
            print(f"多账号执行间隔：{sleep_seconds}")
            use_concurrent = False
        # endregion
        execute()
