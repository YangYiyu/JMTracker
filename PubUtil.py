import re

class Util:
    basic_java_type = [
        "java.lang.String", 
        "java.lang.String[]", 
        "org.json.JSONObject", 
        "org.json.JSONArray"]
    frida_type_dict = {
                    "int": "I",
                    "byte": "B",
                    "short": "S",
                    "long": "J",
                    "float": "F",
                    "double": "D",
                    "char": "C",
                    "boolean": "Z"
                }
    frida_type_dict_reverse = {v:k for k,v in frida_type_dict.items()}

    # 从方法签名中提取基本元素
    @staticmethod
    def extract_method_factor(methodSignature):
        methodSignREResult = re.match(r"(.*) (.*)\((.*)\)", methodSignature, re.I)
        retType = ""
        classPath = ""
        methodName = ""
        paraTypeList = []
        if methodSignREResult:
            retType = methodSignREResult.group(1)
            classPath = ".".join(methodSignREResult.group(2).split(".")[:-1])
            methodName = methodSignREResult.group(2).split(".")[-1]
            paraTypeList = methodSignREResult.group(3).replace(" ", "").split(",")
        return {"ret":retType, "class":classPath, "method":methodName, "paraTypeList":paraTypeList}
    
    # 从带有实例值的方法签名中提取基本元素，不同之处是方法参数列表中是用中文，分开每个参数
    @staticmethod
    def extract_instance_factor(instanceSignature):
        methodSignREResult = re.match(r"(.*) (.*)\((.*)\)", instanceSignature, re.S)
        retType = ""
        classPath = ""
        methodName = ""
        paraTypeList = []
        if methodSignREResult:
            retType = methodSignREResult.group(1)
            classPath = ".".join(methodSignREResult.group(2).split(".")[:-1])
            methodName = methodSignREResult.group(2).split(".")[-1]
            paraTypeList = methodSignREResult.group(3).split("，")
        return {"ret":retType, "class":classPath, "method":methodName, "paraTypeList":paraTypeList}

    # 检查方法methodnode的返回值或者参数里面是否包含基本Java类型
    @staticmethod
    def contain_basic_type_data(methodSignature):
        methodObj = Util.extract_method_factor(methodSignature)
        if any([methodObj["ret"]==t for t in Util.basic_java_type]):
            return True
        else:
            for p in methodObj["paraTypeList"]:
                p = p.strip()
                if any([p==t for t in Util.basic_java_type]):
                    return True
        return False

    # 在frida的hook脚本中，传给overload方法的参数转换规则：
    #   - 如果不是数组，不用转换，填写原始Java类型
    #   - 如果是数组，则要转换：
    #       - int, byte, short, long, float, double, char, boolean基本类型的数组，转为“[”+Smail简写类型，比如“int[]”转为“[I”，“long[]”转为“[J”
    #       - 其他类的数组，转为“[L”+完整类名+“;”，比如“java.lang.String”转为“[Ljava.lang.String;”
    def frida_type_convert(paratype):
        paratype = paratype.strip()
        if paratype[-2:] != "[]":
            return paratype

        typePreStr = paratype.replace("[]", "")
        if "." in typePreStr:
            typeConvertStr = "[L{};".format(typePreStr)
        else:
            typeConvertStr = "[{}".format(Util.frida_type_dict[typePreStr])
        return typeConvertStr

    def frida_type_convert_reverse(paratype):
        paratype = paratype.strip()
        convertResult = paratype
        if paratype[:1] != "[":
            return convertResult

        convertResult = convertResult.replace("[", "")
        if convertResult[-1:] == ";":
            convertResult = convertResult[1:-1]
        else:
            convertResult = Util.frida_type_dict_reverse[convertResult]

        return "{}[]".format(convertResult)

    # 将方法签名转换成Frida Hook脚本的代码，类似Jadx的功能
    @staticmethod
    def frida_method(retStr, classStr, methodStr, paraList, overloads):
        js = "Java.perform(function x() {\n"
        paraList = list(map(Util.frida_type_convert, paraList))
        paraListStr = ",".join([f"'{p}'" for p in paraList])

        classNameStr = classStr.split(".")[-1].replace("$", "_")
        methodStr = methodStr.replace("<init>", "$init") if "<init>" in methodStr else methodStr
        js += f"    let {classNameStr} = Java.use(\"{classStr}\");\n"
        if len(paraList)>0:
            paraListSimStr = ",".join([f"p{i}" for i in range(1,len(paraList)+1)])
        else:
            paraListSimStr = ""
        paraInsStr = ", ".join([f"{pi}=${{{pi}}}" for pi in paraListSimStr.split(",")])
        if overloads>1:
            js += f"    {classNameStr}[\"{methodStr}\"].overload({paraListStr}).implementation = function ({paraListSimStr}) {{\n"
            js += f"        console.log(`{classNameStr}.{methodStr} is called: {paraInsStr}`);\n"
            if retStr=="void":
                js += f"        this[\"{methodStr}\"]({paraListSimStr});\n"
                js += f"    }};\n"
            else:
                js += f"        let result = this[\"{methodStr}\"]({paraListSimStr});\n"
                js += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js += f"        return result;\n"
                js += f"    }};\n"
        elif len(paraList)>0 and len(paraList[0])>0:
            js += f"    {classNameStr}[\"{methodStr}\"].implementation = function ({paraListSimStr}) {{\n"
            js += f"        console.log(`{classNameStr}.{methodStr} is called: {paraInsStr}`);\n"
            if retStr=="void":
                js += f"        this[\"{methodStr}\"]({paraListSimStr});\n"
                js += f"    }};\n"
            else:
                js += f"        let result = this[\"{methodStr}\"]({paraListSimStr});\n"
                js += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js += f"        return result;\n"
                js += f"    }};\n"
        else:
            js += f"{classNameStr}[\"{methodStr}\"].implementation = function () {{\n"
            js += f"        console.log(`{classNameStr}.{methodStr} is called`);\n"
            if retStr=="void":
                js += f"        this[\"{methodStr}\"]();\n"
                js += f"    }};\n"
            else:
                js += f"        let result = this[\"{methodStr}\"]();\n"
                js += f"        console.log(`{classNameStr}.{methodStr} result=${{result}}`);\n"
                js += f"        return result;\n"
                js += f"    }};\n"
    
        js += "});"

        return js
    
    @staticmethod
    def get_flatten_methods_recur(rootJson):
        flatten_method_list = [rootJson["method"]]
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                flatten_method_list += Util.get_flatten_methods_recur(child)

        return flatten_method_list

    # 将树的所有节点拉平成一个列表
    @staticmethod
    def get_flatten_method_list(rootJson):
        flatten_method_list = Util.get_flatten_methods_recur(rootJson)
        # new_flatten_method_list=list(set(flatten_method_list)) # 去重
        # new_flatten_method_list.sort(key=flatten_method_list.index) # 保持原序

        return flatten_method_list

    @staticmethod
    def get_basic_type_methods_recur(rootJson):
        basic_type_method_list = []
        if Util.contain_basic_type_data(rootJson["method"]):
            basic_type_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                basic_type_method_list += Util.get_basic_type_methods_recur(child)

        return basic_type_method_list
    
    # 从树里面找出返回值或参数包含基本Java类型的方法
    @staticmethod
    def get_basic_type_method_list(rootJson):
        basic_type_method_list = Util.get_basic_type_methods_recur(rootJson)
        new_basic_type_method_list=list(set(basic_type_method_list)) # 去重
        new_basic_type_method_list.sort(key=basic_type_method_list.index) # 保持原序

        return new_basic_type_method_list
    
    @staticmethod
    def get_string_methods_recur(rootJson):
        string_method_list = []
        if rootJson["hasstring"]=="1":
            string_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                string_method_list += Util.get_string_methods_recur(child)

        return string_method_list
    
    # 从树里面找出带有String值的方法
    @staticmethod
    def get_string_method_list(rootJson):
        string_method_list = Util.get_string_methods_recur(rootJson)
        # new_string_method_list=list(set(string_method_list)) # 去重
        # new_string_method_list.sort(key=string_method_list.index) # 保持原序

        return string_method_list
    
    @staticmethod
    def get_instance_methods_recur(rootJson):
        instance_method_list = []
        if "instance"in rootJson and rootJson["instance"]:
            instance_method_list.append(rootJson["method"])
        if "children" in rootJson and len(rootJson["children"])>0:
            for child in rootJson["children"]:
                instance_method_list += Util.get_instance_methods_recur(child)

        return instance_method_list

    # 从树里面找出有instance值的节点，并且去重和保持原序
    @staticmethod
    def get_instance_method_list(rootJson):
        instance_method_list = Util.get_instance_methods_recur(rootJson)
        new_instance_method_list=list(set(instance_method_list))
        new_instance_method_list.sort(key=instance_method_list.index)

        return new_instance_method_list

if __name__=="__main__":
    print()