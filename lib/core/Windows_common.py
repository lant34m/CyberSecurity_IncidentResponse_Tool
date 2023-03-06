from Windows_option import *
import os, sys, json, re, time, logging
from imp import reload
from lib.core.globalvar import *
import datetime, win32com.client
import subprocess

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf-8')

# 用于url提取境外IP信息
ip_http = r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
lan_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'

# 恶意特征列表list
malware_infos = []


# 更改Windows Powershell执行策略
# def get_execution_policy():
# command = "powershell Get-ExecutionPolicy"
# result = subprocess.check_output(command, shell=True)
# 将输出转换为字符串并去除末尾的换行符
# policy = result.decode("utf-8").rstrip()
# set_value('Get-ExecutionPolicy', policy)


# 当字典中存在执行策略为
def set_execution_policy():
    command = "powershell Get-ExecutionPolicy"
    result = subprocess.check_output(command, shell=True)
    # 将输出转换为字符串并去除末尾的换行符
    policy = result.decode("utf-8").rstrip()
    if (get_value('SYS_PATH') == None):
        command = "powershell Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine"
        subprocess.run(command, shell=True)
        command = "powershell Get-ExecutionPolicy -Scope LocalMachine"
        result = subprocess.check_output(command, shell=True)
        new_policy = result.decode("utf-8").rstrip()
        print("用户域执行策略修改为：%s" % new_policy)
    else:
        ever_policy = get_value('Get-ExecutionPolicy')
        command = "powershell Set-ExecutionPolicy -ExecutionPolicy " + ever_policy + " -Scope LocalMachine"
        subprocess.run(command,shell=True)
        print("用户域执行策略修改为初值：%s" % ever_policy)
    set_value('Get-ExecutionPolicy', policy)


# 写定时任务信息
def cron_write():
    SYS_PATH = get_value('SYS_PATH')

    scheduler = win32com.client.Dispatch('Schedule.Service')  # 创建Schedule.Service COM组件的实例，用于管理计划任务
    scheduler.Connect()  # 连接到计划任务服务
    root_folder = scheduler.GetFolder('\\')  # 获取计划任务的根文件夹
    task_def = scheduler.NewTask(0)

    # 创建trigger
    start_time = datetime.datetime.now() + datetime.timedelta(days=1)  # 获取当前时间，加上5分钟作为计划任务的开始时间
    TASK_TRIGGER_TIME = 1  # 设置任务触发器类型为时间触发器
    trigger = task_def.Triggers.Create(TASK_TRIGGER_TIME)  # 创建任务触发器
    trigger.StartBoundary = start_time.isoformat()  # 设置任务触发器的开始时间

    # 创建计划任务动作
    TASK_ACTION_EXEC = 0  # 任务动作类型为执行命令
    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.ID = 'CSSCAN'  # 给任务动作命名
    action.Path = 'python.exe'  # 指定要执行的命令解释器

    action.Arguments = SYS_PATH + '\Scan.py'  # 指定要执行的命令参数

    # 设置计划任务参数
    task_def.RegistrationInfo.Description = 'CSSCAN'
    task_def.Settings.Enabled = True
    task_def.Settings.StopIfGoingOnBatteries = False

    TASK_CREATE_OR_UPDATE = 6  # 设置任务注册类型为创建或更新任务
    TASK_LOGON_NONE = 0  # 设置任务登录类型为无登录
    root_folder.RegisterTaskDefinition(
        'Test Task',  # Task name
        task_def,
        TASK_CREATE_OR_UPDATE,
        '',  # No user
        '',  # No password
        TASK_LOGON_NONE)  # 将计划任务定义注册到计划任务服务中。如果任务已存在，则更新任务
    return True


# 创建日志文件
def mkfile():
    SYS_PATH = get_value('SYS_PATH')
    LOG_PATH = get_value('LOG_PATH')
    DB_PATH = get_value('DB_PATH')
    # 判断日志目录是否存在，不存在则创建日志目录
    if not os.path.exists(SYS_PATH + '/log/'): os.mkdir(SYS_PATH + '/log/')
    if not os.path.exists(SYS_PATH + '/db/'): os.mkdir(SYS_PATH + '/db/')
    # 判断日志文件是否存在，不存在则创建,存在则情况
    f = open(LOG_PATH, "w")
    f.truncate()
    f.close()
    # 判断本地数据文件是否存在，不存在则创建
    if not os.path.exists(DB_PATH):
        f = open(DB_PATH, "w")
        f.truncate()
        f.close()


# 获取配置文件的恶意域名等信息
def get_malware_info(path):
    try:
        malware_path = path + '/lib/malware/'
        if not os.path.exists(malware_path): return
        for file in os.listdir(malware_path):
            with open(malware_path + file) as f:
                for line in f:
                    malware = line.strip().replace('\n', '')
                    if len(malware) > 5:
                        if malware[0] != '#' and malware[0] != '.' and ('.' in malware):
                            malware_infos.append(malware)
    except:
        return


# 追加文件写入
def file_write(content):
    LOG_PATH = get_value('LOG_PATH')
    with open(LOG_PATH, 'a+') as f:
        f.write(content)
    sys.stdout.flush()
    return
