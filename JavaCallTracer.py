import re
from MethodNode import MethodNode
from PubUtil import Util

class JavaTracer:
    def __init__(self, appInspector):
        self.appInspector = appInspector
        self.indirect_node_pair = []
        node_java_lang_Thread_start = MethodNode(className="java.lang.Thread", methodName="start", retType="void")
        node_java_lang_Thread_run = MethodNode(className="java.lang.Thread", methodName="run", retType="void")
        self.indirect_node_pair.append((node_java_lang_Thread_start, node_java_lang_Thread_run))

    def extract_call_pair(self, callStr, mode="JAVA_CALL"):
        if mode=="JAVA_CALL":
            callREResult = re.match(r"\[PerformCall\] (.*) --> (.*)", callStr, re.I)
            callorStr = "NaN"
            calleeStr = "NaN"
            if callREResult:
                callorStr = callREResult.group(1)
                calleeStr = callREResult.group(2)
        return {"caller": Util.extract_method_factor(callorStr), "callee": Util.extract_method_factor(calleeStr)}

    def is_excluded_method(self, methodname):
        systemLib = ["android", "com.google.android", "com.android", "libcore", "dalvik.system", 
                    "sun.misc", "sun.util.locale", "sun.reflect.Reflection", "java", "javax", "okhttp3", "okio"]
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

    # 将(callerNode, calleeNode)这对调用关系，添加到rootNode的树上，递归调用
    def add_node(self, rootNode, callerNode, calleeNode):
        # 如果在树上找到caller，就把callee加到caller的children列表上
        if rootNode == callerNode:
            calleeNode.bindParent(rootNode)
            rootNode.appendChild(calleeNode)
        # 如果没有找到caller，但是找到间接调用caller的节点，就把caller和callee一起加到该节点的children上
        elif self.is_indirect_node_pair(rootNode, callerNode):
            callerNode.bindParent(rootNode)
            rootNode.appendChild(callerNode)
            calleeNode.bindParent(callerNode)
            callerNode.appendChild(calleeNode)
        # 如果都没找到，就到rootNode的children上面继续递归搜索
        else:
            for childNode in rootNode.children:
                self.add_node(childNode, callerNode, calleeNode)

    # add_node方法的另一种实现，不用递归搜索，直接在刚刚处理过的方法里面找，因为callerNode如果能连接到已有的树上，其父节点一定在最近处理过的节点中
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

    def get_node_tree_json(self, rootNode):
        result = {}
        if len(rootNode.children)>0:
            result = {rootNode.signature: [self.get_node_tree_json(child) for child in rootNode.children]}
        else:
            result = {rootNode.signature: ""}
        return result

    def get_node_tree_json_with_time(self, rootNode):
        result = {}
        if len(rootNode.children)>0:
            result = {rootNode.signature_time: [self.get_node_tree_json_with_time(child) for child in rootNode.children]}
        else:
            result = {rootNode.signature_time: ""}
        return result
    
    # 按照EasyUI Treegrid的格式返回JSON数据
    def get_node_treegrid_json(self, rootNode):
        node_json = rootNode.treegrid_format()
        if len(rootNode.children)>0:
            node_json["children"] = [self.get_node_treegrid_json(child) for child in rootNode.children]
        return node_json

    # 将树的所有节点拉平成一个列表
    def get_flatten_method_list(self, rootNode):
        flatten_method_list = [rootNode]
        for child in rootNode.children:
            flatten_method_list += self.get_flatten_method_list(child)

        return flatten_method_list

    # 从树里面找出返回值或参数包含基本Java类型的方法
    def get_basic_type_method_list(self, rootNode):
        basic_type_method_list = []
        if Util.contain_basic_type_data(rootNode.signature):
            basic_type_method_list.append(rootNode)
        for child in rootNode.children:
            basic_type_method_list += self.get_basic_type_method_list(child)

        return basic_type_method_list

    # 通过java方法调用日志构建method calling tree，返回所有树的根节点
    def build_trees_by_java_call(self, calllog_list):
        root_node_list = []
        all_node_list = []
        for calllog in calllog_list:
            tid = calllog[0]
            time = calllog[1]
            log = calllog[2]

            callpair = self.extract_call_pair(log)

            caller_ret = callpair["caller"]["ret"]
            caller_class = callpair["caller"]["class"]
            caller_method = callpair["caller"]["method"]
            caller_para = callpair["caller"]["paraTypeList"]

            callee_ret = callpair["callee"]["ret"]
            callee_class = callpair["callee"]["class"]
            callee_method = callpair["callee"]["method"]
            callee_para = callpair["callee"]["paraTypeList"]

            if not self.is_excluded_method(f"{caller_class}.{caller_method}") or not self.is_excluded_method(f"{callee_class}.{callee_method}"):
                callerNode = MethodNode(caller_class, caller_method, caller_para, caller_ret, time, tid)
                calleeNode = MethodNode(callee_class, callee_method, callee_para, callee_ret, time, tid)
                self.add_node_to_tree(callerNode, calleeNode, root_node_list, all_node_list)
        
        print("build tree completed! Tree: {}, Node: {}".format(len(root_node_list), len(all_node_list)))
        return root_node_list 
    
    # 从树的列表root_node_list里面将重复出现了repeat次数的挑出来
    def pick_tree_by_repeat(self, root_node_list, repeat):
        tree_repeat_dict = {}
        for rnode in root_node_list:
            rnode_json = self.get_node_tree_json(rnode)
            rnode_json_str = str(rnode_json)
            # rnode_json_str = rnode_json_str.replace("'", "\"")
            # print(rnode_json_str.replace("'", "\""))
            if rnode_json_str in tree_repeat_dict:
                tree_repeat_dict[rnode_json_str].append(rnode)
            else:
                tree_repeat_dict[rnode_json_str] = [rnode]

        return [tree_repeat_dict[t_j] for t_j in tree_repeat_dict if len(tree_repeat_dict[t_j])==repeat]

    def get_repeat_trees(self, repeat):
        if not self.appInspector:
            print("Error: the appInspector is None, can not get repeat trees!")
            return
        root_node_list = self.build_trees_by_java_call(self.appInspector.get_java_call_list())
        repeat_trees = self.pick_tree_by_repeat(root_node_list, repeat)
        return repeat_trees

    def build_and_pick_repeat_trees(self, repeat):
        if not self.appInspector:
            print("Error: the appInspector is None, can not get repeat trees!")
            return
        root_node_list = self.build_trees_by_java_call(self.appInspector.get_java_call_list())
        repeat_trees = self.pick_tree_by_repeat(root_node_list, repeat)
        print("pick {} trees".format(len(repeat_trees)))
        origin_method_list = []
        filtter_method_list = []
        for trees in repeat_trees:
            # print(self.get_node_treegrid_json(trees[0]))
            # print("------------- >>>>>> {}".format(len(trees)))
            flatten_methods = self.get_flatten_method_list(trees[0])
            # print([str(m) for m in flatten_methods])
            # print("++++++++++++++++++ flatten")
            origin_method_list += flatten_methods
            basic_methods = self.get_basic_type_method_list(trees[0])
            # print([str(m) for m in basic_methods])
            # print("++++++++++++++++++ basic")
            filtter_method_list += basic_methods
        print("origin_method_list: {}".format(len(origin_method_list)))
        print("filtter_method_list: {}".format(len(filtter_method_list)))
        return {"trees": repeat_trees, "tree_count": len(repeat_trees), "method_count": len(origin_method_list), "data_method_count": len(filtter_method_list)}