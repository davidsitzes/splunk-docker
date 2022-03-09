import logging
import re
import os
import subprocess
from uuid import UUID
from distutils.spawn import find_executable

levelNames = {
    logging.ERROR : 'ERROR',
    logging.WARNING : 'WARN',
    logging.INFO : 'INFO'
}

# keep consistent with DurationUtil.scala
duration_pattern = re.compile('^([1-9][0-9]*)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|ms|cs|ds)$')

JVM_SUPPORTED = ["1.7", "1.8"]


class MADRESTException(Exception):
    def to_json(self):
        return {"message": [{"type": self.level, "text": self.message}]}

    def __init__(self, message, level, status_code=500):
        super(MADRESTException, self).__init__(message)
        self.status_code = status_code
        self.level = levelNames[level]


def get_field(dict, field_name, default=None, is_optional=False):
    """
    Get a field from a dictionary
    return the value from `dict`, None if it does not exist and `is_optional` is set to true, otherwise raise exception
    """

    try:
        return dict[field_name]
    except KeyError as e:
        if default is None:
            if is_optional:
                return None
            else:
                raise MADRESTException("Required parameter '%s' must be given" % field_name, logging.ERROR, status_code=400)
        else:
            return default


def check_allowed_params(args_dict, arg_names):
    extraneous_args = list(set(args_dict).difference(arg_names))
    if len(extraneous_args) > 0:
        raise MADRESTException("Unexpected parameter '%s'" % extraneous_args[0], logging.ERROR, status_code=400)


def check_arrays(args_dict, arg_names):
    for arg in arg_names:
        if not isinstance(args_dict[arg], list):
            raise MADRESTException("Parameter '%s' must be an array" % arg, logging.ERROR, status_code=400)


def parse_bool_str(value):
    if value == "0" or value.lower() == "false":
        return False
    elif value == "1" or value.lower() == "true":
        return True
    else:
        raise ValueError("unable to parse value %s" % value)


def check_int(what, value):
    if type(value) == int:
        return value
    else:
        try:
            if isinstance(value, basestring):
                return int(value)
            else:
                raise ValueError("%s value %s can not be converted to integer" % (what, value))
        except ValueError:
            raise MADRESTException(what + " is not an integer, %s" % type(value), logging.ERROR, status_code=400)


def check_long(what, value):
    if type(value) == long:
        return value
    else:
        try:
            if isinstance(value, (basestring, int)):
                return long(value)
            else:
                raise ValueError("%s value %s can not be converted to long" % (what, value))
        except ValueError:
            raise MADRESTException(what + " is not a long integer, %s" % type(value), logging.ERROR, status_code=400)


def check_float(what, value):
    if type(value) == float:
        return value
    else:
        try:
            if isinstance(value, (basestring, int, long)) and type(value) != bool:
                return float(value)
            else:
                raise ValueError("%s value %s can not be converted to integer" % (what, value))
        except ValueError:
            raise MADRESTException(what + " is not a floating point number", logging.ERROR, status_code=400)


def check_flag(what, flag):
    if type(flag) == bool:
        return flag
    else:
        try:
            if isinstance(flag, basestring):
                return parse_bool_str(flag)
            if isinstance(flag, int) and (flag == 0 or flag == 1):
                return bool(flag)
            else:
                raise ValueError("unable to parse value %s" % flag)
        except Exception:
            raise MADRESTException("unsupported '%s' parameter: %s" % (what, flag), logging.ERROR, status_code=400)


def check_valid_uuid(uuid_str):
    try:
        UUID(uuid_str)
        return uuid_str
    except:
        raise MADRESTException("%s is not a valid uuid" % uuid_str, logging.ERROR, status_code=400)


def check_duration(what, value):
    if isinstance(value, basestring):
        matches = duration_pattern.findall(value)
        if not len(matches):
            raise MADRESTException("%s '%s' is not a valid duration" % (what, value), logging.ERROR, status_code=400)
        else:
            return value
    else:
        raise MADRESTException(what + " is not a duration value", logging.ERROR, status_code=400)


def update_or_keep(updated, original, limits):
    if updated is None:
        return original
    else:
        return original.update(updated, limits)


def discover_jvm():
    java_home_env = os.getenv("JAVA_HOME")

    # distutil.spawn.findexecutable() auto add .exe for win32
    java_cmd = "java"

    found_jvm = {}
    result = {}

    jvm_details = get_jvm_details(java_cmd, True)
    if jvm_details:
        result["active"] = "PATH"
        result["activeRunnable"] = jvm_details["status"]["runnable"]
        found_jvm["PATH"] = jvm_details

    if java_home_env is not None:
        java_cmd = os.path.join(java_home_env, "bin", java_cmd)
        jvm_details = get_jvm_details(java_cmd)
        if jvm_details:
            if "active" not in result or jvm_details["status"]["runnable"]:
                result["active"] = "JAVA_HOME"
                result["activeRunnable"] = jvm_details["status"]["runnable"]
            found_jvm["JAVA_HOME"] = jvm_details

    if len(found_jvm) > 0:
        result["availableJVMs"] = found_jvm
        return result
    else:
        result["ERROR"] = "No JVM Found"
        raise MADRESTException("No JVM Found", logging.ERROR, 404)


def get_jvm_details(java_cmd, is_discovered=False):
    jvm_details = {"path": java_cmd, "status": {"supported": False}}
    fpath, fname = os.path.split(java_cmd)
    try:
        if fpath:
            found_exec = find_executable(fname, fpath)
        else:
            found_exec = find_executable(fname)
        if found_exec:
            jvm_details["path"] = found_exec
            jvm_details["status"]["runnable"] = True
            ver_output = subprocess.check_output([found_exec, "-version"], stderr=subprocess.STDOUT)
            jvm_ver_search = re.search(".*?version\s+[\"]?(\\d+[.]\\d+.*?_\\d+)", ver_output)
            if jvm_ver_search:
                jvm_ver_str = jvm_ver_search.group(1)
                jvm_details["version"] = jvm_ver_str
                jvm_ver_parts_search = re.search("(\\d+\.\\d+)\..*", jvm_ver_str)
                if jvm_ver_parts_search:
                    major_ver = jvm_ver_parts_search.group(1)
                    if major_ver not in JVM_SUPPORTED:
                        jvm_details["status"]["ERROR"] = "Unsupported JVM version: %s, JVM supported: %s" % (jvm_ver_str, str(JVM_SUPPORTED))
                    else:
                        jvm_details["status"]["supported"] = True
                else:
                    jvm_details["status"]["ERROR"] = "Unable to parse version number [%s] of the JVM" % jvm_ver_str
            else:
                jvm_details["status"]["ERROR"] = "Unable to parse JVM version output:\n %s" % ver_output
        else:
            jvm_details["status"]["runnable"] = False
            if is_discovered:
                return None
            else:
                jvm_details["status"]["ERROR"] = "Can't find java executable in the given path"

    except OSError as ose:
        jvm_details["status"]["runnable"] = False
        jvm_details["status"]["ERROR"] = str(ose.strerror)

    except Exception:
        jvm_details["status"]["runnable"] = False
        jvm_details["status"]["ERROR"] = "unable to validate java from %s" % java_cmd

    return jvm_details

