from database.DBService import DBService as dbs
import uuid

from PubUtil import Util

class FormalMethodTree:
    def __init__(self, id="", app="", operation="", treejson="", instancejson="", remark=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.app = app
        self.operation = operation
        self.treejson = treejson
        self.instancejson = instancejson
        self.remark = remark

class FormalMethodTreeService:
    def addTree(self, tree):
        sql = "insert into formal_method_tree(id,app,operation,treejson,instancejson,remark) values('{}','{}','{}','{}','{}','{}')".format(tree.id, tree.app, tree.operation, tree.treejson.replace("'", "\""), tree.instancejson.replace("'", "\""), tree.remark)
        return dbs.execute_update(sql)
    
    def updateTreeInstance(self, treeid, instance):
        sql = "update formal_method_tree set instancejson='{}' where id='{}'".format(instance, treeid)
        return dbs.execute_update(sql)

    def deleteTree(self, tree):
        sql = "delete from formal_method_tree where id='{}'".format(tree.id)
        return dbs.execute_update(sql)
    
    def deleteTreeById(self, id):
        sql = "delete from formal_method_tree where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def deleteTreeByIdList(self, idList):
        sql = "delete from formal_method_tree where id='{}'"
        return all([dbs.execute_update(sql.format(id)) for id in idList])
    
    def getFormalTreeById(self, id):
        sql = "select id,app,operation,treejson,instancejson,remark from formal_method_tree where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        app_ = record[0][1]
        operation_ = record[0][2]
        treejson_ = record[0][3]
        instancejson_ = record[0][4]
        remark_ = record[0][5]
        return FormalMethodTree(id_, app_, operation_, treejson_, instancejson_, remark_)

    def getAllFormalTree(self, app, operation, page, rows):
        sql = "select id,app,operation,treejson,instancejson,remark from formal_method_tree where 1=1"
        if app:
            sql += " and app like '%{}%'".format(app)
        if operation:
            sql += " and operation like '%{}%'".format(operation)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "app":rec[1], "operation":rec[2], "treejson":rec[3], "instancejson":rec[4], "remark":rec[5]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def combineInstanceToOneTree(self, insMap, rootJson, stringifyInstance=False):
        method_sign = rootJson["method"]
        method_sign_factors = Util.extract_method_factor(method_sign)
        method_sign = "{} {}.{}({})".format(method_sign_factors["ret"], method_sign_factors["class"], method_sign_factors["method"].replace("<init>", "$init"), ",".join(method_sign_factors["paraTypeList"]))

        if method_sign in insMap:
            if stringifyInstance:
                rootJson["instance"] = "<insep>".join(insMap[method_sign])
            else:
                rootJson["instance"] = insMap[method_sign]
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                self.combineInstanceToOneTree(insMap, child, stringifyInstance)
        return rootJson
    
    # 将insMap中包含的实例值合并到trees的各个方法上
    def combineInstancetoTrees(self, insMap, trees, stringifyInstance=False):
        new_trees = []
        for root in trees:
            new_trees.append(self.combineInstanceToOneTree(insMap, root, stringifyInstance))
        return new_trees
    
    # 删除不包含instance值的节点
    def filter_instance_methods(self, rootJson):
        if "children" in rootJson and len(rootJson["children"])>0:
            for i in range(len(rootJson["children"])-1,-1,-1):
                child = rootJson["children"][i]
                self.filter_instance_methods(child)
                if ("children" not in child or len(child["children"])==0) and ("instance" not in child or len(child["instance"])==0):
                    rootJson["children"].pop(i)