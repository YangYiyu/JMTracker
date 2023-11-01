import time
import frida
import json
import numpy as np
import copy
import signal

from MethodNode import MethodNode

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class MyCrushException(Exception):
    pass

class MyStuckException(Exception):
    pass

class AppInspector:
    def __init__(self, appname="", pkgname=""):
        self.appname = appname
        self.pkgname = pkgname

        self.device = None
        self.session = None
        self.script = None
        self.rpc = None

        self.inherit_class_pair_cache = {}
        self.java_call_list = []
        self.smali_invoke_list = []
        self.instance_map = {}

        self.running = False
        self.stuck = False
        self.destroy = False

        self.initial()

    def initial(self):
        self.inherit_class_pair_cache = {}
        self.java_call_list = []
        self.smali_invoke_list = []

        # signal.signal(signal.SIGUSR1, self.signal_handler)

    def attach_to_app(self, phone_serial="", spawn=False, js_script="HookScript.js"):
        # 连接安卓机上的frida-server
        if len(phone_serial)>0:
            self.device = frida.get_device(phone_serial)
        else:
            self.device = frida.get_usb_device()
        
        if spawn:
            pid = self.device.spawn([self.pkgname])
            self.device.resume(pid)
            time.sleep(1)  # Without it Java.perform silently fails
            self.session = self.device.attach(pid)
        else:
            self.session = self.device.attach(self.pkgname)
        
        self.session.enable_jit() # 开启ES6支持
        
        script_str = ""
        with open(js_script, mode='r', encoding='UTF-8') as f:
            script_str += f.read()
        self.script = self.session.create_script(script_str)
        self.script.on("message", self.my_message_handler)  # 消息处理回调
        self.script.on("destroyed", self.my_destroy_handler)  # app崩溃回调
        self.script.load()
        self.rpc = self.script.exports

        self.running = True

    def my_message_handler(self, message, data):
        if message['type'] == 'send':
            # print(bcolors.OKGREEN + "[*Payload]" + bcolors.ENDC + " " + message['payload'])
            pl = message['payload']
            # print(bcolors.OKGREEN + "[*Payload]" + bcolors.ENDC + " " + pl)
            pl_json = json.loads(pl)
            
            if pl_json["msgtype"] == "java_call":
                tid = pl_json["tid"]
                time = pl_json["time"]
                log = pl_json["log"]
                self.java_call_list.append((tid, time, log))

            elif pl_json["msgtype"] == "smali_invoke":
                tid = pl_json["tid"]
                time = pl_json["time"]
                log = pl_json["log"]
                self.smali_invoke_list.append((tid, time, log))
            
            elif pl_json["msgtype"] == "objects":
                try:
                    # 下面这段转换是为了保证获取的值可以正常显示到treegrid组件上，并且可以保存到数据库中
                    # - Null/None 等空值转为空字符串
                    # - 值里面的双引号全部转为单引号
                    if not pl_json["retvalue"]["obj_value"]:
                        pl_json["retvalue"]["obj_value"] = ""
                    pl_json["retvalue"]["obj_value"] = pl_json["retvalue"]["obj_value"].replace("\"","'")
                    for i in range(len(pl_json["paravalues"])):
                        if not pl_json["paravalues"][i]["obj_value"]:
                            pl_json["paravalues"][i]["obj_value"] = ""
                        pl_json["paravalues"][i]["obj_value"] = pl_json["paravalues"][i]["obj_value"].replace("\"","'")

                    method_signature = "{} {}.{}({})".format(pl_json["methodInfo"]["ret_type"], pl_json["methodInfo"]["class_name"], pl_json["methodInfo"]["method_name"], ",".join(pl_json["methodInfo"]["parameter_type"]))
                    method_instance = "{} {}.{}({})".format(pl_json["retvalue"]["obj_value"], pl_json["methodInfo"]["class_name"], pl_json["methodInfo"]["method_name"], "，".join([v["obj_value"] for v in pl_json["paravalues"]]))

                    if method_signature not in self.instance_map:
                        self.instance_map[method_signature] = []
                    self.instance_map[method_signature].append(method_instance)
                    
                    # print("{} invoked: {} ...".format(method_signature, method_instance))
                except Exception as e:
                    print("[Exception] {}".format(pl_json))
        
        elif message['type'] == 'error':
            print(bcolors.FAIL + "[*Error]" + bcolors.ENDC + " " + message['description'])
            # print("[-stack] " + message['stack'])
            # print("[-fileName] " + message['fileName'])
            # print("[-lineNumber] {}".format(message['lineNumber']))
            # print("[-columnNumber] {}".format(message['columnNumber']))
        else:
            print(message)
  
    def my_destroy_handler(self):
        self.destroy = True
        if self.running and self.stuck:
            print("The hooking process is stucked!")
            # raise MyStuckException("The hooking process is stucked!")
        elif not self.running:
            print("The app is killed actively!")
        else:
            print("Oops, the app is crashed!")
            # raise MyCrushException("The app is crashed!")
        # if os is not None:
            # os.kill(os.getpid(), signal.SIGUSR1) # 给主线程发中断
        self.running = False

    # 系统软中断处理函数，只有Linux系统才可以用
    # def signal_handler(self, sig, frame):
    #     if sig == signal.SIGUSR1:
    #         raise Exception("Caugth signal " + str(sig))

    def kill_app(self, pkgname):
        try:
            print("Kill the app ......")
            process = self.device.get_process(pkgname)
            self.device.kill(process.pid)
            self.running = False
            # self.execute_adb_shell_cmd("am force-stop {}".format(pkgname))
            # time.sleep(1)
        except frida.ProcessNotFoundError:
            print("Kill app failed, " + pkgname + " is not found")
        except Exception as e:
            print(e)

    def reboot_app(self, pkgname):
        try:
            print("Reboot the app ......")
            process = self.device.get_process(pkgname)
            self.device.resume(process.pid)
            self.running = False
        except Exception as e:
            print(e)

    # hook一个方法
    def hookOneMethod(self, methodNode, recordObjFlag=False):
        try:
            self.rpc.hookonemethod(methodNode.className, methodNode.methodName, methodNode.paraTypeList, methodNode.retType, recordObjFlag)
            return True
        except Exception as e:
            print("We have a exception when hook {}.{}".format(methodNode.classname, methodNode.methodname))
            print(e)
            return False
    
    # hook一批方法
    def hookMultiMethods(self, methodNodeList, recordObjFlag=False):
        methods = []
        for node in methodNodeList:
            methods.append([node.className, node.methodName, node.paraTypeList, node.retType])
        try:
            self.rpc.hookmultimethods(methods, recordObjFlag)
            return True
        except Exception as e:
            print("We have a exception when hook {} methods".format(len(methods)))
            print(e)
            return False
        
    # 停止hook一个方法
    def stopHookOneMethod(self, methodNode):
        try:
            self.rpc.stophookonemethod(methodNode.className, methodNode.methodName, methodNode.paraTypeList)
            return True
        except Exception as e:
            print("We have a exception when stop hook {}.{}".format(methodNode.classname, methodNode.methodname))
            print(e)
            return False

    # 判断childClassName和parentClassName是否存在继承关系
    def is_child_and_parent_class(self, childClassName, parentClassName):
        # 为了减少查询次数，用一个dict将已经查过的信息缓存起来
        if (childClassName, parentClassName) in self.inherit_class_pair_cache:
            return self.inherit_class_pair_cache[(childClassName, parentClassName)]
        else:
            r = self.rpc.ischildandparent(childClassName, parentClassName)
            self.inherit_class_pair_cache[(childClassName, parentClassName)] = r
            return r

    # 获取某个方法的重载个数
    def get_method_overloads(self, className, methodName):
        return self.rpc.getmethodoverloads(className, methodName)

    def read_config_file(self, filepath):
        config_dic = {}
        with open(filepath) as f:
            for line in f.read().splitlines():
                key_value = line.split("=")
                config_dic[key_value[0]] = key_value[1]
        return config_dic

    # 返回java_call_list，然后将其清空
    def get_java_call_list(self):
        call_list = copy.deepcopy(self.java_call_list)
        self.java_call_list.clear()

        return call_list
    
    # 清空java_call_list
    def clear_java_call_list(self):
        count = len(self.java_call_list)
        self.java_call_list.clear()

        return count
    
    # 返回smali_invoke_list，然后将其清空
    def get_smali_invoke_list(self):
        invoke_list = copy.deepcopy(self.smali_invoke_list)
        self.smali_invoke_list.clear()

        return invoke_list
    
    # 清空smali_invoke_list
    def clear_smali_invoke_list(self):
        count = len(self.smali_invoke_list)
        self.smali_invoke_list.clear()

        return count

    # 返回method_instance_map，然后将其清空
    def get_method_instance(self):
        method_instance_map = copy.deepcopy(self.instance_map)
        self.instance_map.clear()

        return method_instance_map
    
    # 清空instance_map
    def clear_instance_map(self):
        count = len(self.instance_map)
        self.instance_map.clear()

        return count
    
    def begin_trace(self):
        self.rpc.trace()

    def stop_trace(self):
        self.rpc.canceltrace()

if __name__=="__main__":
    inspector = AppInspector("Xiaomi Mihome", "com.xiaomi.smarthome")
    inspector.attach_to_app("9A181FFBA001HT")
    input()
    # inspector.build_and_pick_repeat_trees(3)