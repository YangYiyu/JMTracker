import uuid
import json

from database.DBService import DBService as dbs

class MethodChain:
    def __init__(self, id="", platform="", capability="", chainjson="", trigger="", remark="", methodnum="", timecost=""):
        if id:
            self.id = id
        else:
            self.id = uuid.uuid1()
        self.platform = platform
        self.capability = capability
        self.chainjson = chainjson
        self.trigger = trigger
        self.remark = remark
        self.methodnum = methodnum
        self.timecost = timecost

class MethodChainService:
    def addTree(self, tree):
        print(tree.chainjson)
        tree.chainjson = tree.chainjson.replace("'", "''")
        sql = "insert into method_chain(id,platform,capability,chainjson,trigger,remark,methodnum,timecost) values('{}','{}','{}','{}','{}','{}','{}','{}')".format(tree.id, tree.platform, tree.capability, tree.chainjson, tree.trigger, tree.remark, tree.methodnum, tree.timecost)
        return dbs.execute_update(sql)

    def updateTrigger(self, id, trigger):
        sql = "update method_chain set trigger='{}' where id='{}'".format(trigger, id)
        return dbs.execute_update(sql)

    def deleteTree(self, tree):
        sql = "delete from method_chain where id='{}'".format(tree.id)
        return dbs.execute_update(sql)
    
    def deleteTreeById(self, id):
        sql = "delete from method_chain where id='{}'".format(id)
        return dbs.execute_update(sql)
    
    def deleteTreeByIdList(self, idList):
        sql = "delete from method_chain where id='{}'"
        return all([dbs.execute_update(sql.format(id)) for id in idList])
    
    def getMethodChainById(self, id):
        sql = "select id,platform,capability,chainjson,trigger,remark,methodnum,timecost from method_chain where id='{}'".format(id)
        record = dbs.execute_query(sql)
        id_ = record[0][0]
        platform_ = record[0][1]
        capability_ = record[0][2]
        chainjson_ = record[0][3]
        trigger_ = record[0][4]
        remark_ = record[0][5]
        methodnum_ = record[0][6]
        timecost_ = record[0][7]
        return MethodChain(id_, platform_, capability_, chainjson_, trigger_, remark_, methodnum_, timecost_)

    def getAllMethodChain(self, platform, capability, page, rows):
        sql = "select id,platform,capability,chainjson,trigger,remark,methodnum,timecost from method_chain where 1=1"
        if platform:
            sql += " and platform like '%{}%'".format(platform)
        if capability:
            sql += " and capability like '%{}%'".format(capability)
        records = dbs.execute_query(sql)
        records_page = records[(page-1)*rows:page*rows]
        result = {}
        record_json = []
        for rec in records_page:
            record_json.append({"id":rec[0], "platform":rec[1], "capability":rec[2], "chainjson":rec[3], "trigger":rec[4], "remark":rec[5], "methodnum":rec[6], "timecost":rec[7]})
        result["total"] = len(records)
        result["rows"] = record_json
        return result
    
    def cleanTreegridJsonQuote(self, jsonObj):
        if "instance" in jsonObj and len(jsonObj["instance"])>0:
            jsonObj["instance"] = jsonObj["instance"].replace("'", "\\'").replace("\"", "\\\"")
        if "children" in jsonObj and len(jsonObj["children"])>0:
            for child in jsonObj["children"]:
                self.cleanTreegridJsonQuote(child)
