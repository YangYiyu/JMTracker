from database.DBService import DBService as dbs
import uuid
import time
import json

from PubUtil import Util

class TempMethodTree:
    def __init__(self, id="", name="", treejson="", operation="", rtime=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.name = name
        self.treejson = treejson
        self.operation = operation
        if rtime:
            self.rtime = rtime
        else:
            self.rtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

class TempMethodTreeService:
    def addTree(self, tree):
        sql = "insert into temp_method_tree(id, name,nodejson,time,operation) values('{}','{}','{}','{}','{}')".format(tree.id, tree.name, tree.treejson.replace("'", "\""), tree.rtime, tree.operation)
        return dbs.execute_update(sql)
    
    def deleteTree(self, tree):
        sql = "delete from temp_method_tree where id='{}'".format(tree.id)
        return dbs.execute_update(sql)
    
    def deleteTreeById(self, id):
        sql = "delete from temp_method_tree where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def deleteTreeByIdList(self, idList):
        sql = "delete from temp_method_tree where id='{}'"
        return all([dbs.execute_update(sql.format(id)) for id in idList])
    
    def getTempTreeById(self, id):
        sql = "select id,name,nodejson,time,operation from temp_method_tree where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        name_ = record[0][1]
        treejson_ = record[0][2]
        operation_ = record[0][3]
        rtime_ = record[0][4]
        return TempMethodTree(id_, name_, treejson_, operation_, rtime_)

    def getAllTempTree(self, name, page, rows):
        sql = "select id,name,nodejson,time,operation from temp_method_tree where 1=1"
        if name:
            sql += " and name like '%{}%'".format(name)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "name":rec[1], "treejson":rec[2], "rtime":rec[3], "operation":rec[4]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
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
        
    def mergeMultiTrees(self, treelist):
        merge_name = "merge_{}".format(int(round(time.time() * 1000)))
        merge_operation = "merge"
        id1 = treelist.pop(0)
        tree1_json = json.loads(self.getTempTreeById(id1).treejson)
        merge_operation += " "+id1
        while len(treelist)>0:
            id2 = treelist.pop(0)
            tree2_json = json.loads(self.getTempTreeById(id2).treejson)
            tree1_json = self.getTwoTreeJsonIntersection(tree1_json, tree2_json)
            merge_operation += ","+id2
        return self.addTree(TempMethodTree(name=merge_name, treejson=json.dumps(tree1_json), operation=merge_operation))