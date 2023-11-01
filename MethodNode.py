import uuid
import time
import random
from PubUtil import Util

class MethodNode:
    def __init__(self, className="", methodName="", paraTypeList=[], retType="", callee_time=0, tid=0, convert=0, instance=""):
        self.className = className
        self.methodName = methodName
        self.paraTypeList = paraTypeList
        self.retType = retType
        self.signature = "{} {}.{}({})".format(retType, className, methodName, ",".join(paraTypeList))
        self.signature_time = "[{}]{} {}.{}({})".format(callee_time, retType, className, methodName, ",".join(paraTypeList))
        self.signature_instance = instance
        self.convert = convert # 这个标志，0就是啥也不干
        if len(paraTypeList) > 0:
            self.paratypeConvert(self.convert)

        # 以下是用于构造method calling tree的属性
        self.callee_time = callee_time
        self.tid = tid
        self.parent = None
        self.children = []
        self.id = str(uuid.uuid3(uuid.NAMESPACE_DNS, "{}@{}-{}".format(self.signature, self.callee_time, random.randint(1, 1000))))
    
    # convertType: 1表示从Java类型转为Frida类型，2表示从Frida类型转为Java类型
    def paratypeConvert(self, convertType):
        if convertType == 1:
            self.paraTypeList = list(map(Util.frida_type_convert, self.paraTypeList))
        elif convertType == 2:
            self.paraTypeList = list(map(Util.frida_type_convert_reverse, self.paraTypeList))

    def __eq__(self, obj):
        if isinstance(obj, MethodNode):
            if self.signature == obj.signature:
                return True
            else:
                return False
        else:
            return False
    
    def __str__(self):
        return self.signature
    
    def treegrid_format(self):
        tree_json = {"id": self.id, "method": self.signature, "tid": self.tid, "time": self.callee_time, "instance": self.signature_instance}
        if self.signature_instance:
            tree_json["instance"] = self.signature_instance

        if "@red_start@" in self.signature_instance:
            tree_json["hasstring"] = "1"
        else:
            tree_json["hasstring"] = "0"

        tree_json["method"] = tree_json["method"].replace("<","&lt;").replace(">","&gt;")

        if not self.parent:
            tree_json["root"] = "1"
        else:
            tree_json["root"] = "0"
            
        tree_json["time"] = self.convert_time(tree_json["time"])
        tree_json["iconCls"] = "icon-arrow"
        return tree_json
    
    def convert_time(self, time_):
        time_str = str(time_)
        time_s_str = time_str[:-3]
        time_ms_str = time_str[-3:]
        time_s_format = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(time_s_str)))
        return "{}.{}".format(time_s_format, time_ms_str)

    def bindParent(self, parent):
        self.parent = parent

    def appendChild(self, child):
        self.children.append(child)