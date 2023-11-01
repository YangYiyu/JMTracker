import re
from MethodNode import MethodNode
from PubUtil import Util

class SmaliTracer:
    def __init__(self, appInspector):
        self.appInspector = appInspector
        self.indirect_node_pair = []
        node_java_lang_Thread_start = MethodNode(className="java.lang.Thread", methodName="start", retType="void")
        node_java_lang_Thread_run = MethodNode(className="java.lang.Thread", methodName="run", retType="void")
        self.indirect_node_pair.append((node_java_lang_Thread_start, node_java_lang_Thread_run))

    def is_excluded_method(self, methodname):
        systemLib = ["android", "com.google.android", "com.android", "libcore", "dalvik.system", 
                    "sun.misc", "sun.util.locale", "sun.reflect.Reflection"]
        return any([methodname.startswith(lib) for lib in systemLib])

    # lastCallee和currentCaller是两个方法，看它们是否存在间接调用关系
    def is_indirect_node_pair(self, lastCallee, currentCaller):
        if not self.appInspector:
            print("Error: the appInspector is None, can not inspect indirect relationship of {}.{} and {}.{}".format(lastCallee.className, lastCallee.methodName, currentCaller.className, currentCaller.methodName))
            return False

        # 两个间接调用之间的时间差阈值不超过100ms
        if currentCaller.callee_time-lastCallee.callee_time>100:
            return False
        # 先查间接调用关系表indirect_node_pair，如果完全匹配上了，就视为满足
        elif (lastCallee, currentCaller) in self.indirect_node_pair:
            return True
        # 没有的话，那么只能与indirect_node_pair里面的方法逐个比较，如果方法名称一样，而且类是关系表里面类的子类，那么也视为满足
        else:
            for pair in self.indirect_node_pair:
                if lastCallee.methodName==pair[0].methodName and currentCaller.methodName==pair[1].methodName:
                    if self.appInspector.is_child_and_parent_class(lastCallee.className, pair[0].className) and self.appInspector.is_child_and_parent_class(currentCaller.className, pair[1].className):
                        return True
            return False

    def add_node_to_tree(self, callerNode, calleeNode, root_node_list, all_node_list):
        # print(f"Adding: [{callerNode.tid}][{callerNode.callee_time}]:{callerNode.retType} {callerNode.className}.{callerNode.methodName}({callerNode.paraTypeList}) --> {calleeNode.retType} {calleeNode.className}.{calleeNode.methodName}({calleeNode.paraTypeList})")
        for lastNode in reversed(all_node_list):
            # 一般情况下，方法调用之间的时间间隔很小（10ms以内），只有涉及UI操作时候的时间间隔会比较长（100ms-300ms）
            if lastNode == callerNode and calleeNode.callee_time-lastNode.callee_time<300:
                calleeNode.bindParent(lastNode)
                lastNode.appendChild(calleeNode)
                all_node_list.append(calleeNode)
                return
            elif self.is_indirect_node_pair(lastNode, callerNode):
                callerNode.bindParent(lastNode)
                lastNode.appendChild(callerNode)
                calleeNode.bindParent(callerNode)
                callerNode.appendChild(calleeNode)
                all_node_list.append(callerNode)
                all_node_list.append(calleeNode)
                return
        if not calleeNode.parent:
            calleeNode.bindParent(callerNode)
            callerNode.appendChild(calleeNode)
            root_node_list.append(callerNode)
            all_node_list.append(callerNode)
            all_node_list.append(calleeNode)

    # 从smali trace中提取出三元组(caller_method, callee_method, callee_method_instance)
    def smali_extract_caller_callee_instance(self, trace):
        # print(trace)
        caller_inst_regs = self.smali_extract_caller_inst_regs(trace)
        caller_method = caller_inst_regs[0]
        callee_inst = caller_inst_regs[1]
        callee_regs = caller_inst_regs[2]

        inst_parse = self.smali_extract_invoke_regindex_callee(callee_inst)
        invoke_inst = inst_parse[0]
        callee_reg_index_list = inst_parse[1]
        callee_method = inst_parse[2]
        callee_reg_value_list = self.smali_extract_reg_value_list(callee_regs)

        if "quick" in invoke_inst and not callee_method:
            callee_method = self.smali_convert_unknown_callee_method(callee_reg_index_list, callee_reg_value_list, invoke_inst)

        callee_method_instance = self.smali_convert_callee_para_value(callee_method, callee_reg_index_list, callee_reg_value_list, invoke_inst)

        return (caller_method, callee_method, callee_method_instance)

    # 从smali trace中提取出三个部分的字符串：caller、inst、regs
    # 一条smali trace的组成：[FuncName] caller [Address] inst [Regs] regs"
    def smali_extract_caller_inst_regs(self, trace):
        reResult = re.match(r"\[FuncName\]\s(.*)\s\[Address\]\s(.*)\s\[Regs\]\s(.*)", trace, re.I|re.S)
        caller_method = ""
        inst = ""
        callee_regs = ""
        if reResult:
            caller_method = reResult.group(1).strip()
            inst = reResult.group(2).strip()
            callee_regs = reResult.group(3).strip()
        return (caller_method, inst, callee_regs)

    # 从smali trace的inst部分提取出(smali指令、参数寄存器的编号数组、被调用的方法（签名）)
    def smali_extract_invoke_regindex_callee(self, inst):
        reResult = re.match(r".*:\s(.*)\s{(.*)},(.*)\s//.*", inst, re.I|re.S)
        invoke_inst = ""
        reg_index = []
        callee_method = ""
        if reResult:
            invoke_inst = reResult.group(1).strip(" ,")
            reg_str = reResult.group(2).strip(" ,")
            if reg_str:
                if "range" in invoke_inst:
                    r_begin_end = [int(r.strip(" v")) for r in reg_str.split("..")]
                    reg_index = [i for i in range(r_begin_end[0], r_begin_end[1]+1)]
                else:
                    reg_index = [int(i.strip(" v")) for i in reg_str.split(",")]
            else:
                reg_index = []
            callee_method = reResult.group(3).strip(" ,")

        return (invoke_inst, reg_index, callee_method)

    # 从smali trace的regs部分提取出各寄存器的值，每个寄存器的值包含三个部分：寄存器中保存的地址、数据类型（类名）、字符串值（只针对String类型才有）
    def smali_extract_reg_value_list(self, regstr):
        reg_value_list = []
        for reg in regstr.split("vreg"):
            if reg:
                reg = reg.strip()
                reg_value_list.append(self.smali_parse_reg_value(reg[reg.index("=")+1:]))
        return reg_value_list

    # 给定寄存器的值，比如vreg1=0x6FB44260/java.lang.String "data"，返回三元组
    def smali_parse_reg_value(self, regrawvalue):
        rawvalue = ""
        valuetype = ""
        stringvalue = ""
        if "/" in regrawvalue:
            rawvalue = regrawvalue[0:regrawvalue.index("/")]
            valuetype = regrawvalue[regrawvalue.index("/")+1:]
            if "java.lang.String" in valuetype:
                stringvalue = valuetype.replace("java.lang.String", "").strip(" \"")
                valuetype = "java.lang.String"
        else:
            rawvalue = regrawvalue.strip()
        return (rawvalue, valuetype, stringvalue)

    # 如果callee_method的参数是String类型，则将该参数替换为真实的字符串值，返回的还是方法签名的格式
    def smali_convert_callee_para_value(self, callee_method, reg_index_list, reg_value_list, invoke_inst):
        factors = Util.extract_method_factor(callee_method)
        para_type_list = factors["paraTypeList"]
        para_value_list = []
        if len(para_type_list)>0 and para_type_list[0]:
            if "static" in invoke_inst:
                j = 0
                for i in range(0,len(para_type_list)):
                    if para_type_list[i]=="java.lang.String":
                        para_value_list.append("\"@red_start@{}@red_end@\"".format(self.smali_get_reg_value(reg_value_list[reg_index_list[j]])))
                        j += 1
                    elif para_type_list[i]=="double" or para_type_list[i]=="long":
                        para_value_list.append(self.smali_get_reg_value(reg_value_list[reg_index_list[j]])+"-"+self.smali_get_reg_value(reg_value_list[reg_index_list[j+1]]))
                        j += 2
                    else:
                        para_value_list.append(self.smali_get_reg_value(reg_value_list[reg_index_list[j]]))
                        j += 1
            else:
                j = 1
                for i in range(0,len(para_type_list)):
                    if para_type_list[i]=="java.lang.String":
                        para_value_list.append("\"@red_start@{}@red_end@\"".format(self.smali_get_reg_value(reg_value_list[reg_index_list[j]])))
                        j += 1
                    elif para_type_list[i]=="double" or para_type_list[i]=="long":
                        para_value_list.append(self.smali_get_reg_value(reg_value_list[reg_index_list[j]])+"-"+self.smali_get_reg_value(reg_value_list[reg_index_list[j+1]]))
                        j += 2
                    else:
                        para_value_list.append(self.smali_get_reg_value(reg_value_list[reg_index_list[j]]))
                        j += 1

        return "{} {}.{}({})".format(factors["ret"], factors["class"], factors["method"], ",".join(para_value_list))

    def smali_get_reg_value(self, reg_value):
        if reg_value[1]=="java.lang.String":
            return reg_value[2]
        elif reg_value[1]:
            return reg_value[1]
        else:
            return reg_value[0]
        
    def smali_convert_unknown_callee_method(self, reg_index_list, reg_value_list, invoke_inst):
        class_name = "Unknown"
        para_list = []
        if len(reg_index_list)>0:
            if "static" in invoke_inst:
                for index in reg_index_list:
                    if reg_value_list[index][1]:
                        para_list.append(reg_value_list[index][1])
                    else:
                        para_list.append("unknown")
            else:
                if reg_value_list[0][1]:
                    class_name = reg_value_list[0][1]
                for index in reg_index_list[1:]:
                    if reg_value_list[index][1]:
                        para_list.append(reg_value_list[index][1])
                    else:
                        para_list.append("unknown")

        return "Unknown {}.Unknown({})".format(class_name, ",".join(para_list))

    # 删除不包含String值的节点
    def smali_filter_instance_methods(self, rootJson):
        if "children" in rootJson and len(rootJson["children"])>0:
            for i in range(len(rootJson["children"])-1,-1,-1):
                child = rootJson["children"][i]
                self.smali_filter_instance_methods(child)
                if ("children" not in child or len(child["children"])==0) and child["hasstring"]=="0":
                    rootJson["children"].pop(i)

    # 按照EasyUI Treegrid的格式返回JSON数据
    def get_node_treegrid_json(self, rootNode):
        node_json = rootNode.treegrid_format()
        if len(rootNode.children)>0:
            node_json["children"] = [self.get_node_treegrid_json(child) for child in rootNode.children]
        return node_json

    # 通过smali的invoke构建method calling tree，方法中同时带有参数值，返回各树的根节点
    def build_trees_by_smali(self, smalitrace_list):
        root_node_list = []
        all_node_list = []
        for st in smalitrace_list:
            tid = st[0]
            time = st[1]
            trace = st[2]

            caller_callee_instance = self.smali_extract_caller_callee_instance(trace)
            caller_method = caller_callee_instance[0]
            callee_method = caller_callee_instance[1]
            callee_method_instance = caller_callee_instance[2]

            caller_factors = Util.extract_method_factor(caller_method)
            callee_factors = Util.extract_method_factor(callee_method)

            caller_ret = caller_factors["ret"]
            caller_class = caller_factors["class"]
            caller_method = caller_factors["method"]
            caller_para = caller_factors["paraTypeList"]

            callee_ret = callee_factors["ret"]
            callee_class = callee_factors["class"]
            callee_method = callee_factors["method"]
            callee_para = callee_factors["paraTypeList"]

            if not self.is_excluded_method(f"{caller_class}.{caller_method}") or not self.is_excluded_method(f"{callee_class}.{callee_method}"):
                callerNode = MethodNode(caller_class, caller_method, caller_para, caller_ret, time, tid)
                calleeNode = MethodNode(callee_class, callee_method, callee_para, callee_ret, time, tid, 0, callee_method_instance)
                self.add_node_to_tree(callerNode, calleeNode, root_node_list, all_node_list)
        
        print("build tree completed! Tree: {}, Node: {}".format(len(root_node_list), len(all_node_list)))
        return root_node_list

    def grab_smali_trees(self):
        if not self.appInspector:
            print("Error: the appInspector is None, can not get repeat trees!")
            return []
        smali_invoke_list = self.appInspector.get_smali_invoke_list()
        root_node_list = self.build_trees_by_smali(smali_invoke_list)
        return root_node_list
    
    def convertTreegridJsonToNodeCallTreeJson(self, treegridJson):
        callTreeJson = {}
        if "children" in treegridJson and len(treegridJson["children"])>0:
            callTreeJson[treegridJson["method"]] = [self.convertTreegridJsonToNodeCallTreeJson(child) for child in treegridJson["children"]]
        else:
            callTreeJson[treegridJson["method"]] = ""
        return callTreeJson

    def getTwoTreeJsonIntersection(self, tree1_json, tree2_json):
        intersec_json = []
        for tree1_root in tree1_json:
            for tree2_root in tree2_json:
                if self.convertTreegridJsonToNodeCallTreeJson(tree1_root) == self.convertTreegridJsonToNodeCallTreeJson(tree2_root):
                    intersec_json.append(tree1_root)
        return intersec_json