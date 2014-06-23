#coding:utf-8
import ConfigParser

def config_parser(conf_path):
    cf = ConfigParser.ConfigParser()
    cf.read(conf_path) #另个方法是cf.readfp(fp) fp是已打开的文件对象
    # 列出所有sections
    sec = cf.sections()
    pos = cf.options("KEY")
    #直接读取配置值
    conf_file = cf.get("KEY","keyfile")
    return conf_file
