function getStackTrace() {
    console.log("------------Stack Trace----------------->")
    var throwableClz = Java.use("java.lang.Throwable");
    var traceElements = throwableClz.$new().getStackTrace();
    traceElements.forEach(function (ele) {
        console.log(ele);
    });
    console.log("<----------------------------------------")
}

function onMessage(value) {
    var type = value.type;
    var payload = value.payload;
    console.log("receive message : " + JSON.stringify(value));

    if (type == "exit") {
        console.log("process exit");
        return;
    }

    if (type == "invoke") {
        var hookMethodJson = JSON.parse(payload);
        var clazzStr = hookMethodJson.className;
        var methodStr = hookMethodJson.methodName;
        var parameterTypeArray = hookMethodJson.paraTypeList;
        hookOneFunction(clazzStr, methodStr, parameterTypeArray);
    }

    recv(onMessage);
    console.log("waiting for message ......");
}

function getParaListStr(paralist) {
    return paralist.join(",");
}

var java_to_smali_dict = {
    "short": "S",
    "int": "I",
    "double": "D",
    "void": "V",
    "float": "F",
    "long": "J",
    "char": "C",
    "boolean": "Z",
    "byte": "B"
}
var smali_to_java_dict = {
    "S": "short",
    "I": "int",
    "D": "double",
    "V": "void",
    "F": "float",
    "J": "long",
    "C": "char",
    "Z": "boolean",
    "B": "byte"
}

var java_basic_types = ['java.lang.String', 'java.lang.String[]', 'org.json.JSONObject', 'org.json.JSONArray'];

var smali_basic_types = ['Ljava.lang.String;', '[Ljava.lang.String;', 'Lorg.json.JSONObject;', 'Lorg.json.JSONArray;'];

var thisObject = null;
var retObject = null;

function java_array_convert_to_frida(java_type) {
    if(java_type.substr(java_type.length-2) === '[]') {
        var j_type = java_type.replaceAll('[]', '');
        if(java_to_smali_dict[j_type] !== undefined) 
            return '['+java_to_smali_dict[j_type]
        else
            return '['+j_type.replaceAll('.', '/')+';'
    }
    return java_type;
}

function byteToHexStr(byte) {
    var _ret = '0x';
    if (byte <= 0xf) {
        _ret += '0';
    }
    _ret += byte.toString(16);
    return _ret;
}

/**
 * 给定一个对象，返回该对象转换成String的值（只处理basic_types中的类型）
 * @param {java.lang.String} type 对象类型
 * @param {Object} value 对象引用
 * @returns 字符串值
 */
function getPrimitiveVal(type, value) {
    var _value = '';

    if(!value)
        return '';

    if (type === '[Ljava.lang.String;') {
        Java.perform(function () {
            try {
                var ArrayClz = Java.use("java.lang.reflect.Array");
                var len = ArrayClz.getLength(value);
                for(var i=0;i!=len;i++){
                    if(i>0) {
                        _value += ',';
                    }
                    _value += ArrayClz.get(value,i).toString();
                }
            } catch (e) {
                _value = '';
            }
        });
    }
    else {
        try {
            _value = value.toString();
        } catch (e) {
            _value = '';
        }
    }
    return _value;
}

/**
 * 给定一个实例对象，解析该对象的值。
 * 如果该对象属于基本类型，就直接返回值；否则按照深度优先遍历内部的所有子对象，直到遇到基本类型或无法解析。
 * 注意控制解析深度，太深的解析会耗费内存和时间，引起app卡死。
 * @param {java.lang.String} objName 表示对象全称，比如“com.xiaomi.smarthome.core.service.request 
 * @param {java.lang.String} objType 表示对象类型，比如“com.xiaomi.smarthome.net.BaseRequest 
 * @param {java.lang.Object} obj 表示对象引用，比如“BaseRequest req = new BaseRequest()”里面的“req” 
 * @returns 一个dict，其中包含对象名称、对象类型、对象的值，对象的值是一个字符串。
 */
function getObjectVal(objName, objType, obj){
    var _value = {};
    _value['obj_name'] = objName;
    _value['obj_type'] = objType;
    _value['obj_value'] = 'uninitialized';

    if(!obj) { 
        _value['obj_value'] = String(obj);
    }
    else {
        // 如果objType是基本类型，则直接用getPrimitiveVal转化
        if (java_basic_types.indexOf(objType) >= 0 || smali_basic_types.indexOf(objType) >= 0){
            _value['obj_value'] = getPrimitiveVal(objType, obj);
        }
        // 如果是对象类型
        else {
            _value['obj_value'] = obj.toString();
        }
    }

    return _value;
}

/**
 * hook一个方法
 * @param {java.lang.String} clazzStr 类全称
 * @param {java.lang.String} methodStr 方法名称
 * @param {java.util.Array} parameterTypeArray 参数类型数组，字符串数组
 * @param {java.lang.String} retType 返回值
 * @param {boolean} recordObjFlag true|false，是否记录并发送实时值，记录的对象包括：参数，返回值
 */
function hookOneMethod(clazzStr, methodStr, parameterTypeArray, retType, recordObjFlag) {
    setImmediate(function() {
        Java.perform(function x() {
            if(clazzStr.length==0 || methodStr.length==0 || methodStr=="<clinit>") {
                return;
            }
            if(methodStr=="<init>") {
                methodStr = "$init";
            }
    
            try {
                var hookclazz = Java.use(clazzStr);
                // console.log("load " + clazzStr + " successfully!!");
                var parameterTypeArray_trim = parameterTypeArray.map((x) => x.trim());
                var h = undefined;
                if(hookclazz[methodStr].overloads.length==1) {
                    h = hookclazz[methodStr];
                }
                else if(parameterTypeArray_trim.length==1 && parameterTypeArray_trim[0].length==0) {
                    h = hookclazz[methodStr].overload();
                }
                else {
                    h = hookclazz[methodStr].overload(...parameterTypeArray_trim);
                }

                // var methods = hookclazz.class.getDeclaredMethods();
                // var m = undefined;
                // for(var i=0;i<methods.length;i++) {
                //     if(methods[i].toString().indexOf(retType+' '+clazzStr+'.'+methodStr+'('+parameterTypeArray.join()+')')>0) {
                //         m = methods[i]
                //         break;
                //     }
                // }
                // if(m) {
                //     var modifers = Java.use('java.lang.reflect.Modifier').toString(m.getModifiers());
                //     if(modifers.indexOf('synchronized')>0) {
                //         return;
                //     }
                // }

                h.implementation = function f() {
                    // 为方便参数处理，先转为array
                    var args = Array.prototype.slice.call(arguments, f.length);
    
                    var msg = {};
                    msg['msgtype'] = 'objects';
                    var methodInfo = {}; // 方法的基本信息
                    methodInfo['class_name'] = clazzStr;
                    methodInfo['method_name'] = methodStr;
                    methodInfo['parameter_type'] = parameterTypeArray_trim;
                    methodInfo['ret_type'] = retType;
                    msg['methodInfo'] = methodInfo;
                    msg['time'] = new Date().getTime();
                    msg['paravalues'] = [];
                    msg['retvalue'] = {};
    
                    if(recordObjFlag) {
                        // 记录参数的值
                        for(var i=0;i<args.length;i++) {
                            msg['paravalues'].push(getObjectVal('arg['+i+']', parameterTypeArray_trim[i], args[i]));
                        }
                    }
    
                    var ret_val = this[methodStr].apply(this, args);
    
                    if(recordObjFlag) {
                        msg['retvalue'] = getObjectVal('ret', retType, ret_val);
                        if(retType==='void') {
                            msg['retvalue']['obj_value'] = '';
                        }
                        send(JSON.stringify(msg));
                    }
        
                    return ret_val;
                }
                // console.log("hook " + clazzStr + "." + methodStr + " successfully!");
        
            } catch (e) {
                console.log("HookScript captured exception: " + e.message + ", method: " + retType + " " + clazzStr + "." + methodStr + "(" + parameterTypeArray_trim.join() + ")");
            }
        });
    });
}

/**
 * 停止hook一个方法
 * @param {java.lang.String} clazzStr 类全称
 * @param {java.lang.String} methodStr 方法名称
 * @param {java.util.Array} parameterTypeArray 参数类型数组，字符串数组
 */
function stopHookOneMethod(clazzStr, methodStr, parameterTypeArray) {
    setImmediate(function() {
        Java.perform(function x() {
            if(clazzStr.length==0 || methodStr.length==0 || methodStr=="<clinit>") {
                return;
            }
            if(methodStr=="<init>") {
                methodStr = "$init";
            }
    
            try {
                var hookclazz = Java.use(clazzStr);
                var parameterTypeArray_trim = parameterTypeArray.map((x) => x.trim());
                var h = undefined;
                if(hookclazz[methodStr].overloads.length==1) {
                    h = hookclazz[methodStr];
                }
                else if(parameterTypeArray_trim.length==1 && parameterTypeArray_trim[0].length==0) {
                    h = hookclazz[methodStr].overload();
                }
                else {
                    h = hookclazz[methodStr].overload(...parameterTypeArray_trim);
                }
                h.implementation = null;
        
            } catch (e) {
                console.log("HookScript captured exception: " + e.message + ", stop hook method: " + retType + " " + clazzStr + "." + methodStr + "(" + parameterTypeArray_trim.join() + ")");
            }
        });
    });
}

/**
 * hook一批方法
 * @param {java.lang.Array} hooks 方法数组
 * @param {boolean} recordObjFlag true|false，是否记录并发送实时值，记录的对象包括：参数，返回值
 */
function hookMultiMethods(hooks, recordObjFlag) {
    setImmediate(function() {
        Java.perform(function x() {
            for(var hook of hooks) {
                var clazzStr = hook[0];
                var methodStr = hook[1];
                var parameterTypeArray = hook[2];
                var retType = hook[3];

                if(clazzStr.length==0 || methodStr.length==0 || methodStr=="<clinit>") {
                    continue;
                }
                if(methodStr=="<init>") {
                    methodStr = "$init";
                }
        
                try {
                    var hookclazz = Java.use(clazzStr);
                    // console.log("load " + clazzStr + " successfully!!");
                    var parameterTypeArray_trim = parameterTypeArray.map((x) => x.trim());
                    var h = undefined;
                    if(hookclazz[methodStr].overloads.length==1) {
                        h = hookclazz[methodStr];
                    }
                    else if(parameterTypeArray_trim.length==1 && parameterTypeArray_trim[0].length==0) {
                        h = hookclazz[methodStr].overload();
                    }
                    else {
                        h = hookclazz[methodStr].overload(...parameterTypeArray_trim);
                    }
                    h.implementation = function f() {
                        var args = Array.prototype.slice.call(arguments, f.length);
        
                        var msg = {};
                        msg['msgtype'] = 'objects';
                        var methodInfo = {}; // 方法的基本信息
                        methodInfo['class_name'] = clazzStr;
                        methodInfo['method_name'] = methodStr;
                        methodInfo['parameter_type'] = parameterTypeArray_trim;
                        methodInfo['ret_type'] = retType;
                        msg['methodInfo'] = methodInfo;
                        msg['time'] = new Date().getTime();
                        msg['paravalues'] = [];
                        msg['retvalue'] = {};
        
                        if(recordObjFlag) {
                            // 记录参数的值
                            for(var i=0;i<args.length;i++) {
                                msg['paravalues'].push(getObjectVal("arg["+i+"]", parameterTypeArray_trim[i], args[i]));
                            }
                        }
        
                        var ret_val = this[methodStr].apply(this, args);
        
                        if(recordObjFlag) {
                            // 记录返回值
                            msg['retvalue'] = getObjectVal("ret", retType, ret_val);
                        }
                        send(JSON.stringify(msg));

                        return ret_val;
                    }
                    // console.log("hook " + clazzStr + "." + methodStr + " successfully!");
                } catch (e) {
                    console.log("HookScript captured exception: " + e.message + ", method: " + retType + " " + clazzStr + "." + methodStr + "(" + parameterTypeArray_trim.join() + ")");
                }
            }
        });
    });
}

/**
 * 停止hook一批方法
 * @param {java.lang.Array} hooks 方法数组
 */
function stopHookMultiMethods(hooks) {
    setImmediate(function() {
        Java.perform(function x() {
            for(var hook of hooks) {
                var clazzStr = hook[0];
                var methodStr = hook[1];
                var parameterTypeArray = hook[2];

                if(clazzStr.length==0 || methodStr.length==0 || methodStr=="<clinit>") {
                    continue;
                }
                if(methodStr=="<init>") {
                    methodStr = "$init";
                }
        
                try {
                    var hookclazz = Java.use(clazzStr);
                    var parameterTypeArray_trim = parameterTypeArray.map((x) => x.trim());
                    var h = undefined;
                    if(hookclazz[methodStr].overloads.length==1) {
                        h = hookclazz[methodStr];
                    }
                    else if(parameterTypeArray_trim.length==1 && parameterTypeArray_trim[0].length==0) {
                        h = hookclazz[methodStr].overload();
                    }
                    else {
                        h = hookclazz[methodStr].overload(...parameterTypeArray_trim);
                    }
                    h.implementation = null;
                } catch (e) {
                    console.log("HookScript captured exception: " + e.message + ", stop hook method: " + retType + " " + clazzStr + "." + methodStr + "(" + parameterTypeArray_trim.join() + ")");
                }
            }
        });
    });
}

/**
 * 判断给定的两个类是否存在继承关系
 * @param {*} childClassName 
 * @param {*} parentClassName 
 * @returns 
 */
function isChildAndParent(childClassName, parentClassName) {
    // console.log("JS compare "+childClassName+" : "+parentClassName);
    var result = false;
    Java.perform(function() {
        var childClass = Java.use(childClassName).class;
        while(childClass !== null && childClass !== undefined
            && childClass.getName() !== 'java.lang.Object' 
            && childClass.getName() !== 'java.lang.Class') {
                if(childClass.getName()===parentClassName) {
                    result = true;
                    break;
                }
                else
                    childClass = childClass.getSuperclass();
            }
    });
    // console.log("JS compare result:"+result);
    return result;
}

/**
 * 获得某个方法的重载次数
 * @param {*} className 
 * @param {*} methodName 
 * @returns 
 */
function getMethodOverloads(className, methodName) {
    var overloads = 0;
    if(methodName=="<init>") {
        methodName = "$init";
    }
    Java.perform(function() {
        var hookclazz = Java.use(className);
        overloads = hookclazz[methodName].overloads.length;
    });
    return overloads;
}

function HookLog(log, type, sendlog=false) {
    var threadid = Process.getCurrentThreadId();
    var time = new Date().getTime();
    // var consolelog = "[" + threadid + "][" + time + "]:";
    // if(type=="java_call_log")
    //     consolelog += "JAVA_CALL --- " + log;
    // else if(type=="jni_call_log")
    //     consolelog += "JNI_CALL --- " + log;
    // console.log(consolelog);
    // console.log("--------------------------");

    if(sendlog) {
        var msg = {};
        msg["msgtype"] = type;
        msg["tid"] = threadid;
        msg["time"] = time;
        msg["log"] = log;
        send(JSON.stringify(msg));
    }
}

function trace() {
    var libcModule = Process.getModuleByName("libc.so");
    var strstrAddr = libcModule.getExportByName("strstr");
    //console.log(strstrAddr)
    console.log("Tracing is beginning ......");
    Interceptor.attach(strstrAddr, {
        onEnter: function (args) {
            this.arg0 = ptr(args[0]).readUtf8String();
            this.arg1 = ptr(args[1]).readUtf8String();
            
            // jni call
            // if(this.arg1.indexOf("InvokeWithArgArrayBefore") != -1) { //jni
            //     if(this.arg0.indexOf("withCleanCallingIdentity") != -1)
            //         LogPrint("JNI_CALL"+ "---" + this.arg0);
            // }
            
            // java call
            // if(this.arg1.indexOf("PerformCallBefore") != -1) {
                // HookLog(this.arg0, "java_call", true);
                // if(this.arg0.indexOf("stub")>0) {
                //     console.log(this.arg0);
                // }
            // }
            
            // smali instruction
            if(this.arg1 && this.arg1.indexOf("myTraceExecutionBefore") != -1) {
                // if(this.arg0.indexOf("invoke-virtual")>0 && this.arg0.indexOf("invoke-virtual-quick")<0 && this.arg0.indexOf("range-quick")<0) {
                if(this.arg0.indexOf("invoke")>0) {
                    // console.log(this.arg0);
                    HookLog(this.arg0, "smali_invoke", true);
                }
            }

        }, 
        onLeave: function (retval) {
            if(this.arg1 && this.arg1.indexOf("ExecuteSwitchImplCppBefore") != -1) {
                retval.replace(1);
            }
        }
    });
}

function cancelTrace() {
    console.log("Tracing is stopping ......");
    Interceptor.detachAll();
}

function hookJavaMethod() {
    var clazzStr = '_m_j.dni';
    var methodStr = 'getDid';
    var parameterTypeArray = ''.split(",");
    var retType = 'java.lang.String';
    var recordObjFlag = true;
    setImmediate(function() {
        Java.perform(function x() {
            if(clazzStr.length==0 || methodStr.length==0 || methodStr=="<clinit>") {
                return;
            }
    
            try {
                var hookclazz = Java.use(clazzStr);
                console.log("load " + clazzStr + " successfully!!");
                console.log(hookclazz[methodStr].overloads.length);
                // var parameterTypeArray_trim = parameterTypeArray.map((x) => x.trim());
                // var h = undefined;
                // if(hookclazz[methodStr].overloads.length==1) {
                //     h = hookclazz[methodStr];
                // }
                // else if(parameterTypeArray_trim.length==1 && parameterTypeArray_trim[0].length==0) {
                //     h = hookclazz[methodStr].overload();
                // }
                // else {
                //     h = hookclazz[methodStr].overload(...parameterTypeArray_trim);
                // }
                
                // var methods = hookclazz.class.getDeclaredMethods();
                // var m = undefined;
                // for(var i=0;i<methods.length;i++) {
                //     if(methods[i].toString().indexOf(retType+' '+clazzStr+'.'+methodStr+'('+parameterTypeArray.join()+')')>0) {
                //         m = methods[i]
                //         break;
                //     }
                // }
                // var modifers = Java.use('java.lang.reflect.Modifier').toString(m.getModifiers());

                // h.implementation = function f() {
                //     var args = Array.prototype.slice.call(arguments, f.length);
    
                //     var msg = {};
                //     msg['msgtype'] = 'objects';
                //     var methodInfo = {}; // 方法的基本信息
                //     methodInfo['class_name'] = clazzStr;
                //     methodInfo['method_name'] = methodStr;
                //     methodInfo['parameter_type'] = parameterTypeArray_trim;
                //     methodInfo['ret_type'] = retType;
                //     msg['methodInfo'] = methodInfo;
                //     msg['paravalues'] = [];
                //     msg['retvalue'] = {};
    
                //     if(recordObjFlag) {
                //         for(var i=0;i<args.length;i++) {
                //             msg['paravalues'].push(getObjectVal("arg["+i+"]", parameterTypeArray_trim[i], args[i]));
                //         }
                //     }
    
                //     var ret_val = this[methodStr].apply(this, args);
    
                //     if(recordObjFlag) {
                //         msg['retvalue'] = getObjectVal("ret", retType, ret_val);
                //         send(JSON.stringify(msg));
                //     }
        
                //     return ret_val;
                // }
                // console.log("hook " + clazzStr + "." + methodStr + " successfully!");
        
            } catch (e) {
                console.log("HookScript captured exception: " + e.message + ", method: " + retType + " " + clazzStr + "." + methodStr + "(" + parameterTypeArray_trim.join() + ")");
            }
        });
    });
}

// trace();
// hookJavaMethod();
// console.log("Script loaded successfully!");

// recv(onMessage);
// console.log("waiting for message ......");

rpc.exports = {
    hookonemethod : hookOneMethod,
    hookmultimethods : hookMultiMethods,
    stophookonemethod : stopHookOneMethod,
    stophookmultimethods: stopHookMultiMethods,
    ischildandparent : isChildAndParent,
    getmethodoverloads : getMethodOverloads,
    trace : trace,
    canceltrace : cancelTrace
};