import json
import time

from flask import Flask
from flask import request, redirect, url_for, render_template

from HookLoader import bcolors, AppInspector
from MethodNode import MethodNode
from JavaCallTracer import JavaTracer
from SmaliInvokerTracer import SmaliTracer
from database.TempMethodTreeService import TempMethodTree, TempMethodTreeService
from database.FormalMethodTreeService import FormalMethodTree, FormalMethodTreeService
from database.MethodChainService import MethodChain, MethodChainService
from PubUtil import Util

app = Flask(__name__, template_folder="html")
inspector = None
java_tracer = None
smali_tracer = None
temp_method_tree_service = TempMethodTreeService()
formal_method_tree_service = FormalMethodTreeService()
method_chain_service = MethodChainService()
already_hooked_method = []

@app.route("/")
def default():
    return render_template("MainPage.html")

@app.route("/MethodTreePage")
def MethodTreePage():
    return render_template("MethodTreePage.html")

@app.route("/ManageTempTreePage")
def ManageTempTreePage():
    return render_template("ManageTempTreePage.html")

@app.route("/ManageFormalTreePage")
def ManageFormalTreePage():
    return render_template("ManageFormalTreePage.html")

@app.route("/BuildSmaliChainPage")
def BuildSmaliChainPage():
    return render_template("BuildSmaliChainPage.html")

@app.route("/MergeSmaliChainPage")
def MergeSmaliChainPage():
    return render_template("MergeSmaliChainPage.html")

@app.route("/ManageChainPage")
def ManageChainPage():
    return render_template("ManageChainPage.html")

@app.route("/hookapp", methods=["GET", "POST"])
def hookapp():
    global inspector
    global java_tracer
    global smali_tracer

    appname = request.form.get("appname")
    pkgname = request.form.get("pkgname")
    try:
        inspector = AppInspector(appname, pkgname)
        inspector.attach_to_app("9A181FFBA001HT")
        inspector.begin_trace()

        java_tracer = JavaTracer(inspector)
        smali_tracer = SmaliTracer(inspector)

        return {"msg": "success"}
    except Exception as e:
        print(e)
        return {"msg": str(e)}

@app.route("/stoptrace", methods=["GET", "POST"])
def stoptrace():
    global inspector
    try:
        inspector.stop_trace()
        return {"msg": "success"}
    except Exception as e:
        print(e)
        return {"msg": str(e)}

@app.route("/rebootapp", methods=["GET", "POST"])
def rebootapp():
    global inspector
    pkgname = request.form.get("pkgname")
    try:
        inspector.reboot_app(pkgname)
        return {"msg": "success"}
    except Exception as e:
        print(e)
        return {"msg": str(e)}

@app.route("/killapp", methods=["GET", "POST"])
def killapp():
    global inspector
    pkgname = request.form.get("pkgname")
    try:
        inspector.kill_app(pkgname)
        return {"msg": "success"}
    except Exception as e:
        print(e)
        return {"msg": str(e)}

@app.route("/gethookstatus", methods=["GET", "POST"])
def gethookstatus():
    global inspector
    if inspector and inspector.running:
        return "running"
    else:
        return "stopped"

@app.route("/getRepeatTreeData", methods=["GET", "POST"])
def getRepeatTreeData():
    global java_tracer
    repeat = int(request.form.get("repeat"))
    result = {}
    treegrid_json = []
    try:
        repeat_trees = java_tracer.build_and_pick_repeat_trees(repeat)
        for trees in repeat_trees["trees"]:
            treegrid_json.append(java_tracer.get_node_treegrid_json(trees[0]))
        result["tree_json"] = treegrid_json
        result["tree_count"] = repeat_trees["tree_count"]
        result["method_count"] = repeat_trees["method_count"]
        result["data_method_count"] = repeat_trees["data_method_count"]
    except Exception as e:
        print(e)

    return result

@app.route("/pickRepeatTrees", methods=["GET", "POST"])
def pickRepeatTrees():
    global java_tracer
    repeat = int(request.form.get("repeat"))
    treegrid_json = []
    try:
        repeat_trees = java_tracer.get_repeat_trees(repeat)
        for trees in repeat_trees:
            treegrid_json.append(java_tracer.get_node_treegrid_json(trees[0]))
    except Exception as e:
        print(e)

    return treegrid_json

@app.route("/getAppnameJSON")
def getAppnameJSON():
    app_list = [
        {"appname":"MyDemo", "pkgname":"com.example.mydemo"},
        {"appname":"Xiaomi Mihome", "pkgname":"com.xiaomi.smarthome"},
        {"appname":"TP-LINK Security", "pkgname":"com.tplink.ipc"},
        {"appname":"Ezviz", "pkgname":"com.videogo"},
        {"appname":"Imou", "pkgname":"com.mm.android.lc"},
        {"appname":"Orvibo", "pkgname":"com.orvibo.homemate"}
    ]
    return app_list

@app.route("/addTempMethodTree", methods=["GET", "POST"])
def addTempMethodTree():
    name_ = request.form.get("name")
    json_ = request.form.get("json")
    operation_ = request.form.get("operation")
    tempTree = TempMethodTree(name=name_, treejson=json_, operation=operation_)
    if temp_method_tree_service.addTree(tempTree):
        return "success"
    else:
        return "failed"

@app.route("/deleteTempMethodTreeByIdList", methods=["GET", "POST"])
def deleteTempMethodTreeByIdList():
    id_list_str = request.form.get("id_list")
    id_list = id_list_str.strip(",").split(",")
    if temp_method_tree_service.deleteTreeByIdList(id_list):
        return 'success'
    else:
        return 'failed'

@app.route("/getTempMethodTree", methods=["GET", "POST"])
def getTempMethodTree():
    name_ = request.form.get("name")
    page = request.form.get("page")
    rows = request.form.get("rows")
    treeJson = temp_method_tree_service.getAllTempTree(name_, int(page), int(rows))
    if treeJson:
        return treeJson
    else:
        return {"total":0,"rows":[]}
    
@app.route("/mergeTempMethodTrees", methods=["GET", "POST"])
def mergeTempMethodTrees():
    tree_id_list_str = request.form.get("tree_id_list")
    tree_id_list = tree_id_list_str.strip(",").split(",")
    if temp_method_tree_service.mergeMultiTrees(tree_id_list):
        return 'success'
    else:
        return 'failed'

@app.route("/getTempTreeStatisticsById", methods=["GET", "POST"])
def getTempTreeStatisticsById():
    result = {}
    tree_id = request.args.get("tree_id")
    tree_json = json.loads(temp_method_tree_service.getTempTreeById(tree_id).treejson)
    result["root_nodes"] = len(tree_json)
    ori_nodes = 0
    basic_nodes = 0
    for root in tree_json:
        ori_nodes += len(Util.get_flatten_method_list(root))
        basic_nodes += len(Util.get_basic_type_method_list(root))
    result["ori_nodes"] = ori_nodes
    result["basic_nodes"] = basic_nodes
    result["tree_json"] = tree_json
    return result
    
@app.route("/addFormalMethodTree", methods=["GET", "POST"])
def addFormalMethodTree():
    app_ = request.form.get("app")
    operation_ = request.form.get("operation")
    treejson_ = request.form.get("treejson")
    instancejson_ = request.form.get("instancejson")
    remark_ = request.form.get("remark")
    formalTree = FormalMethodTree(app=app_, operation=operation_, treejson=treejson_, instancejson=instancejson_, remark=remark_)
    if formal_method_tree_service.addTree(formalTree):
        return "success"
    else:
        return "failed"

@app.route("/deleteFormalMethodTreeByIdList", methods=["GET", "POST"])
def deleteFormalMethodTreeByIdList():
    id_list_str = request.form.get("id_list")
    id_list = id_list_str.strip(",").split(",")
    if formal_method_tree_service.deleteTreeByIdList(id_list):
        return 'success'
    else:
        return 'failed'

@app.route("/getFormalMethodTree", methods=["GET", "POST"])
def getFormalMethodTree():
    app_ = request.form.get("app")
    operation_ = request.form.get("operation")
    page = request.form.get("page")
    rows = request.form.get("rows")
    treeJson = formal_method_tree_service.getAllFormalTree(app_, operation_, int(page), int(rows))
    if treeJson:
        return treeJson
    else:
        return {"total":0,"rows":[]}

@app.route("/getFormalTreeStatisticsById", methods=["GET", "POST"])
def getFormalTreeStatisticsById():
    result = {}
    tree_id = request.args.get("tree_id")
    tree_json = json.loads(formal_method_tree_service.getFormalTreeById(tree_id).treejson)
    result["root_nodes"] = len(tree_json)
    ori_nodes = 0
    basic_nodes = 0
    instance_node = 0
    for root in tree_json:
        ori_nodes += len(Util.get_flatten_method_list(root))
        basic_nodes += len(Util.get_basic_type_method_list(root))
        instance_node += len(Util.get_instance_method_list(root))
    result["ori_nodes"] = ori_nodes
    result["basic_nodes"] = basic_nodes
    result["instance_nodes"] = basic_nodes
    return result

@app.route("/hookFormalTreeBasicMethods", methods=["GET", "POST"])
def hookFormalTreeBasicMethods():
    tree_id = request.form.get("tree_id")
    tree_json = json.loads(formal_method_tree_service.getFormalTreeById(tree_id).treejson.replace("&lt;", "<").replace("&gt;", ">"))
    basic_nodes = []
    hook_methods = []
    for root in tree_json:
        basic_nodes += Util.get_basic_type_method_list(root)

    for basic in basic_nodes:
        factors = Util.extract_method_factor(basic)
        hook_methods.append(MethodNode(className=factors["class"], methodName=factors["method"], paraTypeList=factors["paraTypeList"], retType=factors["ret"], convert=1))

    if inspector:
        for m in hook_methods:
            if inspector.hookOneMethod(m, True):
                # print("hook {} successful".format(m.signature))
                already_hooked_method.append(m)
            else:
                print("hook {} failed !!!!!!!!!!!!!!!!!!!!!!".format(m.signature))
    else:
        print("inspector is None !!!!!!!!!!!!!")
    
    return "success"

@app.route("/clearAlreadyHooks", methods=["GET", "POST"])
def clearAlreadyHooks():
    if inspector:
        for m in already_hooked_method:
            if inspector.stopHookOneMethod(m):
                # print("stop hook {} successful".format(m.signature))
                pass
            else:
                print("stop hook {} failed !!!!!!!!!!!!!!!!!!!!!!".format(m.signature))
        already_hooked_method.clear()
    else:
        print("inspector is None !!!!!!!!!!!!!")

    return "success"
    
@app.route("/getFormalMethodInstanceTree", methods=["GET", "POST"])
def getFormalMethodInstanceTree():
    tree_id = request.args.get("tree_id")
    tree_json = json.loads(formal_method_tree_service.getFormalTreeById(tree_id).treejson.replace("&lt;", "<").replace("&gt;", ">"))
    insMap = inspector.get_method_instance()

    for med in insMap:
        med_factors = Util.extract_method_factor(med)
        new_ins_array = []
        for ins in insMap[med]:
            ins_factors = Util.extract_instance_factor(ins)
            # 给返回值上色
            new_ret = ins_factors["ret"]
            # if med_factors["ret"]=="java.lang.String":
            #     new_ret = "\"{}\"".format(new_ret)
            new_ret = "@red_start@{}@red_end@".format(new_ret)

            # 给参数值上色
            new_para_array = []
            for i in range(len(ins_factors["paraTypeList"])):
                n_p = ins_factors["paraTypeList"][i]
                # if med_factors["paraTypeList"][i]=="java.lang.String":
                #     n_p = "\"{}\"".format(n_p)
                new_para_array.append("@red_start@{}@red_end@".format(n_p))
            
            new_ins = "{} {}.{}({})".format(new_ret, ins_factors["class"], ins_factors["method"], ",".join(new_para_array))
            new_ins_array.append(new_ins)
        insMap[med] = new_ins_array

    tree_json = formal_method_tree_service.combineInstancetoTrees(insMap, tree_json, True)
    return {"inscount": len(insMap),"treejson": json.loads(json.dumps(tree_json).replace("<", "&lt;").replace(">", "&gt;"))}

@app.route("/fridamethod", methods=["GET", "POST"])
def fridamethod():
    result = ""
    method_sign = request.args.get("method")
    if method_sign:
        methodFactors = Util.extract_method_factor(method_sign)
        retStr = methodFactors["ret"]
        classStr = methodFactors["class"]
        methodStr = methodFactors["method"].replace("&lt;", "<").replace("&gt;", ">")
        paraList = methodFactors["paraTypeList"]

        overloads = 1
        if inspector:
            overloads = inspector.get_method_overloads(classStr, methodStr)
        else:
            print("inspector is None !!!!!!!!!!!!!")

        return Util.frida_method(retStr, classStr, methodStr, paraList, overloads)

    return result

@app.route("/updateFormalTreeInstance", methods=["GET", "POST"])
def updateFormalTreeInstance():
    treeid = request.form.get("tree_id")
    instancejson = request.form.get("instance_json")

    instancejson = instancejson.replace("\\n", "").replace("\\", "")
    instancejson = instancejson.replace("'", "''")

    if formal_method_tree_service.updateTreeInstance(treeid, instancejson):
        return "success"
    else:
        return "failed"

@app.route("/getFilteredInstanceTree", methods=["GET", "POST"])
def getFilteredInstanceTree():
    tree_id = request.args.get("tree_id")
    tree_json = json.loads(formal_method_tree_service.getFormalTreeById(tree_id).instancejson.replace("&lt;", "<").replace("&gt;", ">"))
    for i in range(len(tree_json)-1,-1,-1):
        root = tree_json[i]
        formal_method_tree_service.filter_instance_methods(root)
        if "children" not in root or len(root["children"])==0:
            tree_json.pop(i)
    
    result = {}
    result["root_nodes"] = len(tree_json)
    ori_nodes = 0
    basic_nodes = 0
    instance_node = 0
    for root in tree_json:
        ori_nodes += len(Util.get_flatten_method_list(root))
        basic_nodes += len(Util.get_basic_type_method_list(root))
        instance_node += len(Util.get_instance_method_list(root))
    result["ori_nodes"] = ori_nodes
    result["basic_nodes"] = basic_nodes
    result["instance_nodes"] = basic_nodes

    result["treejson"] = json.loads(json.dumps(tree_json).replace("<", "&lt;").replace(">", "&gt;"))

    return result

@app.route("/getSmaliTreeData", methods=["GET", "POST"])
def getSmaliTreeData():
    global smali_tracer
    treegrid_json = []
    try:
        smali_trees = smali_tracer.grab_smali_trees()
        for tree in smali_trees:
            treegrid_json.append(smali_tracer.get_node_treegrid_json(tree))
    except Exception as e:
        print(e)

    return treegrid_json

@app.route("/getSmaliFilteredInstanceTree", methods=["GET", "POST"])
def getSmaliFilteredInstanceTree():
    global smali_tracer
    tree_json = []
    try:
        begin_time = time.time()
        smali_trees = smali_tracer.grab_smali_trees()
        end_time = time.time()
        for tree in smali_trees:
            tree_json.append(smali_tracer.get_node_treegrid_json(tree))
    except Exception as e:
        print(e)
    for i in range(len(tree_json)-1,-1,-1):
        root = tree_json[i]
        smali_tracer.smali_filter_instance_methods(root)
        if "children" not in root or len(root["children"])==0:
            tree_json.pop(i)
    
    result = {}
    result["root_nodes"] = len(tree_json)
    ori_nodes = 0
    string_nodes = 0
    for root in tree_json:
        ori_nodes += len(Util.get_flatten_method_list(root))
        string_nodes += len(Util.get_string_method_list(root))
    result["ori_nodes"] = ori_nodes
    result["string_nodes"] = string_nodes
    result["time_cost"] = end_time-begin_time
    result["treejson"] = json.loads(json.dumps(tree_json).replace("<", "&lt;").replace(">", "&gt;"))

    return result

@app.route("/clearSmaliTrace", methods=["GET", "POST"])
def clearSmaliTrace():
    global inspector
    try:
        count = inspector.clear_smali_invoke_list()
    except Exception as e:
        print(e)

    return {"count": count}

@app.route("/mergeTwoSmaliChain", methods=["GET", "POST"])
def mergeTwoSmaliChain():
    global smali_tracer
    chain1_json = json.loads(request.form.get("chain1"))
    chain1_time = json.loads(request.form.get("time1"))
    chain2_json = json.loads(request.form.get("chain2"))
    chain2_time = json.loads(request.form.get("time2"))
    merged_chain_treejson = smali_tracer.getTwoTreeJsonIntersection(chain1_json, chain2_json)
    
    result = {}
    result["root_nodes"] = len(merged_chain_treejson)
    ori_nodes = 0
    basic_nodes = 0
    instance_node = 0
    for root in merged_chain_treejson:
        ori_nodes += len(Util.get_flatten_method_list(root))
        basic_nodes += len(Util.get_basic_type_method_list(root))
        instance_node += len(Util.get_instance_method_list(root))
    result["ori_nodes"] = ori_nodes
    result["basic_nodes"] = basic_nodes
    result["instance_nodes"] = basic_nodes
    result["time_cost"] = (chain1_time + chain2_time)/2
    result["treejson"] = merged_chain_treejson
    return result
    
@app.route("/addMethodChain", methods=["GET", "POST"])
def addMethodChain():
    platform_ = request.form.get("platform")
    capability_ = request.form.get("capability")
    chainjson_ = request.form.get("chainjson")
    trigger_ = request.form.get("trigger")
    remark_ = request.form.get("remark")
    methodnum_ = request.form.get("methodnum")
    timecost_ = request.form.get("timecost")
    
    methodChain = MethodChain(platform=platform_, capability=capability_, chainjson=chainjson_, trigger=trigger_, remark=remark_, methodnum=methodnum_, timecost=timecost_)
    if method_chain_service.addTree(methodChain):
        return "success"
    else:
        return "failed"

@app.route("/getMethodChain", methods=["GET", "POST"])
def getMethodChain():
    platform_ = request.form.get("platform")
    capability_ = request.form.get("capability")
    page = request.form.get("page")
    rows = request.form.get("rows")
    treeJson = method_chain_service.getAllMethodChain(platform_, capability_, int(page), int(rows))
    if treeJson:
        return treeJson
    else:
        return {"total":0,"rows":[]}

@app.route("/deleteMethodChainByIdList", methods=["GET", "POST"])
def deleteMethodChainByIdList():
    id_list_str = request.form.get("id_list")
    id_list = id_list_str.strip(",").split(",")
    if method_chain_service.deleteTreeByIdList(id_list):
        return 'success'
    else:
        return 'failed'

@app.route("/updateMethodChainTrigger", methods=["GET", "POST"])
def updateMethodChainTrigger():
    id = request.form.get("id")
    trigger = request.form.get("trigger")

    if method_chain_service.updateTrigger(id, trigger):
        return "success"
    else:
        return "failed"

@app.route("/getMethodTrigger", methods=["GET", "POST"])
def getMethodTrigger():
    id = request.args.get("id")
    if id:
        chain_ = method_chain_service.getMethodChainById(id)
        return chain_.trigger

    return ""

if __name__ == "__main__":
    # host: 绑定的ip(域名)
    # port: 监听的端口号
    # debug: 是否开启调试模式
    app.run(host="0.0.0.0", port=8000, debug=True)