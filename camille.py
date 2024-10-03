from utlis import print_msg, write_xlsx, write_json, resource_path
from utlis.simulate_click import SimulateClick
from utlis.device import get_frida_device
from multiprocessing import Process
from sys import exit
import multiprocessing
import traceback
import argparse
import random
import signal
import frida
import time
import sys
import os

try:
    import click
except:
    class click:
        @staticmethod
        def secho(message=None, **kwargs):
            print(message)

        @staticmethod
        def style(**kwargs):
            raise Exception("unsupported style")
try:
    from shutil import get_terminal_size as get_terminal_size
except:
    try:
        from backports.shutil_get_terminal_size import get_terminal_size as get_terminal_size
    except:
        pass

banner = """
-----------------------------------------------------------


 .o88b.  .d8b.  .88b  d88. d888888b db      db      d88888b 
d8P  Y8 d8' `8b 88'YbdP`88   `88'   88      88      88'     
8P      88ooo88 88  88  88    88    88      88      88ooooo 
8b      88~~~88 88  88  88    88    88      88      88~~~~~ 
Y8b  d8 88   88 88  88  88   .88.   88booo. 88booo. 88.     
 `Y88P' YP   YP YP  YP  YP Y888888P Y88888P Y88888P Y88888P 
                                                                                     
            https://github.com/zhengjim/camille
-------------------------------------------------------------\n
"""


def show_banner():
    colors = ['bright_red', 'bright_green', 'bright_blue', 'cyan', 'magenta']
    try:
        click.style('color test', fg='bright_red')
    except:
        colors = ['red', 'green', 'blue', 'cyan', 'magenta']
    try:
        columns = get_terminal_size().columns
        if columns >= len(banner.splitlines()[1]):
            for line in banner.splitlines():
                click.secho(line, fg=random.choice(colors))
    except:
        pass


def frida_hook(device_info, app_name, use_module,
               wait_time=0, is_show=True, execl_file=None, isattach=False, external_script=None):
    """
    :param app_name: 包名
    :param use_module 使用哪些模块
    :param wait_time: 延迟hook，避免加壳
    :param is_show: 是否实时显示告警
    :param execl_file 导出文件
    :param isattach 使用attach hook
    :param external_script 加载外部脚本文件

    :return:
    """

    def my_message_handler(message, payload):
        """ 消息处理 """
        if message["type"] == "error":
            print(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        if message['type'] == 'send':
            data = message["payload"]
            if data["type"] == "notice":
                alert_time = data['time']
                action = data['action']
                arg = data['arg']
                messages = data['messages']
                returnValue = data['returnValue']
                stacks = data['stacks']
                subject_type = tps.is_third_party(stacks)

                if is_show:
                    print("------------------------------start---------------------------------")
                    print("[*] {0}，APP行为：{1}、行为主体：{2}、行为描述：{3}、传入参数：{4}、返回值：{5}".format(
                        alert_time, action, subject_type, messages, arg.replace('\r\n', '，'), returnValue))
                    print("[*] 调用堆栈：")
                    print(stacks)
                    print("-------------------------------end----------------------------------")
                if execl_file:
                    global privacy_policy_status
                    global execl_data
                    truncate_string = lambda s: s[:3200] if len(s) > 3200 else s
                    execl_data.append({
                        # 仅可保留前32767个字符
                        'alert_time': truncate_string(alert_time),
                        'action': truncate_string(action),
                        'messages': truncate_string(messages),
                        'arg': truncate_string(arg),
                        'returnValue': truncate_string(returnValue),
                        'stacks': truncate_string(stacks),
                        'subject_type': truncate_string(subject_type),
                        # 'privacy_policy_status': "同意隐私政策" + truncate_string(privacy_policy_status.value),
                    })
            if data['type'] == "app_name":
                get_app_name = data['data']
                my_data = False if get_app_name == app_name else True
                script.post({"my_data": my_data})
            if data['type'] == "isHook":
                global isHook
                isHook = True
                script.post({"use_module": use_module})
            if data['type'] == "noFoundModule":
                print_msg('输入 {} 模块错误，请检查'.format(data['data']))
            if data['type'] == "loadModule":
                if data['data']:
                    print_msg('已加载模块{}'.format(','.join(data['data'])))
                else:
                    print_msg('无模块加载，请检查')

    tps = device_info["thirdPartySdk"]
    device = device_info["device"]
    try:
        pid = app_name if isattach else device.spawn([app_name])
        time.sleep(1)
        session = device.attach(pid)
        time.sleep(1)
        if external_script:
            if os.path.isabs(external_script):
                external_script = os.path.abspath(external_script)
            else:
                external_script = os.path.join(os.getcwd(), external_script)
        else:
            external_script = os.path.join(os.getcwd(), 'script.js')
        if os.path.isfile(external_script):
            script_path = external_script
        else:
            script_path = resource_path('./script.js')
            not_exists_log = 'the external script file \'%s\' doesn\'t exists' % external_script
            if os.path.isfile(os.path.abspath(script_path)):
                print('Warning: %s，loading built-in script...' % not_exists_log)
            else:
                print('Error: %s!' % not_exists_log)
                exit()
        with open(script_path, encoding="utf-8") as f:
            script_read = f.read()
        if wait_time:
            script_read += "setTimeout(main, {0}000);\n".format(str(wait_time))
        else:
            script_read += "setImmediate(main);\n"
        script = session.create_script(script_read)
        script.on("message", my_message_handler)
        script.load()
        time.sleep(1)
        if not isattach:
            device.resume(pid)
        wait_time += 1
        time.sleep(wait_time)
        if isHook:
            def stop(signum, frame):
                print_msg('You have stoped hook.')
                session.detach()
                print("detach success")
                if execl_file:
                    global execl_data
                    write_json(execl_data, execl_file.replace(".xls", ".json"))
                    write_xlsx(execl_data, execl_file)
                exit()

            signal.signal(signal.SIGINT, stop)
            signal.signal(signal.SIGTERM, stop)
            sys.stdin.read()
        else:
            print_msg("hook fail, try delaying hook, adjusting delay time")
    except frida.NotSupportedError as e:
        if 'unable to find application with identifier' in str(e):
            print_msg('找不到 {} 应用，请排查包名是否正确'.format(app_name))
        else:
            print_msg('frida-server没有运行/frida-server与frida版本不一致，请排查')
            print_msg(e)
    except frida.ProtocolError as e:
        print_msg('frida-server没有运行/frida-server与frida版本不一致，请排查')
        print_msg(e)
    except frida.ServerNotRunningError as e:
        print_msg('frida-server没有运行/没有连接设备，请排查')
        print_msg(e)
    except frida.ProcessNotFoundError as e:
        print_msg("找不到该进程，{}".format(str(e)))
    except frida.InvalidArgumentError as e:
        print_msg("script.js脚本错误，请排查")
        print_msg(e)
    except frida.InvalidOperationError as e:
        print_msg('hook被中断，是否运行其他hook框架(包括其他frida)，请排查')
    except frida.TransportError as e:
        print_msg('hook关闭或超时，是否运行其他hook框架(包括其他frida)/设备是否关闭selinux，请排查')
        print_msg(e)
    except KeyboardInterrupt:
        print_msg('You have stoped hook.')
    except Exception as e:
        print_msg("hook error")
        print(traceback.format_exc())
    finally:
        exit()


def agree_privacy(privacy_policy_status, device_id):
    try:
        # 等待应用启动
        time.sleep(5)
        screen_save_path = '/data/local/tmp'
        sc = SimulateClick(device_id, screen_save_path, 'screen.png')
        screencap_result = sc.run()
        if screencap_result:
            result = sc.get_result()
            while result == 1:
                sc = SimulateClick(device_id, screen_save_path, 'screen.png')
                sc.run()
                result = sc.get_result()
            if result == 2:
                privacy_policy_status.value = '后'
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    # 下面这句必须在if下面添加
    multiprocessing.freeze_support()

    # 这里要移除上一次生成的，否则报错了会用上一次的截屏结果进行显示
    last_screen_shot = os.path.join(os.getcwd(), "screen.png")
    if not os.path.isfile(last_screen_shot):
        last_screen_shot = resource_path("screen.png")
    if os.path.isfile(last_screen_shot):
        os.remove(last_screen_shot)

    show_banner()

    parser = argparse.ArgumentParser(description="App privacy compliance testing.")
    parser.add_argument("package", help="APP_NAME or process ID ex: com.test.demo01 、12345")
    parser.add_argument("--time", "-t", default=0, type=int, help="Delayed hook, the number is in seconds ex: 5")
    parser.add_argument("--noshow", "-ns", required=False, action="store_const", default=True, const=False,
                        help="Showing the alert message")
    parser.add_argument("--file", "-f", metavar="<path>", required=False, help="Name of Excel file to write")
    parser.add_argument("--isattach", "-ia", required=False, action="store_const", default=False, const=True,
                        help="use attach hook")
    parser.add_argument("--noprivacypolicy", "-npp", required=False, action="store_const", default=False, const=True,
                        help="close the privacy policy. after closing, default status is agree privacy policy")

    module_group = parser.add_mutually_exclusive_group()
    module_group.add_argument("--use", "-u", required=False,
                              help="Detect the specified module,Multiple modules are separated by ',' ex:phone,permission")
    module_group.add_argument("--nouse", "-nu", required=False,
                              help="Skip specified module，Multiple modules are separated by ',' ex:phone,permission")

    parser.add_argument("--serial", "-s", required=False,
                        help="use device with given serial(device id), you can get it by exec 'adb devices'")
    parser.add_argument("--host", "-H", required=False,
                        help="connect to remote frida-server on HOST,ex:127.0.0.1:1234")
    parser.add_argument("--external-script", "-es", required=False,
                        help="load external frida script js, default: ./script.js")

    args = parser.parse_args()
    # 全局变量
    isHook = False
    execl_data = []

    use_module = {"type": "all", "data": []}
    if args.use:
        use_module = {"type": "use", "data": args.use}
    if args.nouse:
        use_module = {"type": "nouse", "data": args.nouse}

    frida_device = get_frida_device(args.serial, args.host)
    # 在本版本的应用中, 主要作用是hook一系列函数, 而非进行隐私合规检测, 因此无需此处隐私政策相关检查
    # attach模式不调用同意隐私协议
    # if args.noprivacypolicy or args.isattach:
    #     privacy_policy_status = multiprocessing.Value('u', '后')
    #     agree_privacy_process = None
    # else:
    #     privacy_policy_status = multiprocessing.Value('u', '前')
    #     did = frida_device['did'] if frida_device['did'] else frida_device["device"].id
    #     agree_privacy_process = Process(target=agree_privacy, args=(privacy_policy_status, did))
    #     agree_privacy_process.daemon = True
    #     agree_privacy_process.start()

    process = int(args.package) if args.package.isdigit() else args.package
    frida_hook(frida_device, process, use_module,
               args.time, args.noshow, args.file, args.isattach, args.external_script)
