#encoding:utf-8
import os
import random
import re
import time
import requests
import yaml
import json
import string
import hashlib
import urllib

base_url = "http://127.0.0.1"   #指定target uri

#pcre
ran_num_p = re.compile('randomInt(\d+)')
ran_str_p = re.compile('randomLowercase(\d+)')
md5_p = re.compile('md5(.+)')
domain_p = re.compile('request.url.domain')

#解析单个yaml文件，返回json值
def get_yaml_info(yaml_file):
    with open(yaml_file) as f:
        yaml_content = yaml.load(f,Loader=yaml.SafeLoader)
    return yaml_content

#部分yaml的随机值表达式不适用python,需要转换
#这部分考虑过用eval直接执行，但是太冗余了，还是建议遇到一个特殊的直接写函数返回转换值

"""
内置函数解析默认传入队列，依次转换后返回map直接替换
"""
#返回domain 对应的request.url.domain
def get_domain(url):
    url = base_url  #这里默认是解析指定url的地址，有需要的自己改
    return urllib.parse.urlparse(url).netloc

#返回随机数据值 对应的randomInt
def get_rannum(con):
    ret_map = {}
    #randomInt(?)
    for i in con:
        num = int('\d'.search(i).group(0))
        ret_map[i] = random.randint(num)

    return ret_map

#返回随机字符串 对应的randomLowercase
def get_ranstr(con):
    ret_map = {}
    #randomLowercase(?)
    for i in con:
        s = int('\d'.search(i).group(0))
        ret_map[i] = ''.join(random.choices(string.ascii_lowercase, k=s))

    return ret_map

#返回md5  对应的md5
def get_md5(con):
    ret_map = {}
    #md5(?)
    for i in con:
        m = i.split('(')[1].strip(')')
        ret_map[i] = hashlib.md5(m.encode()).hexdigest()

    return ret_map

def transform_expression(expre_list):
    """
    转换的格式之后需要在for里加
    把python没有的和工具内置函数处理写字符串，eval执行
    返回随机生成函数执行后的结果set
    现在统计结果以下几个随机值生成函数
    """
    for tran_index in expre_list.keys():
        #这里建议用正则匹配
        ran_num_list = ran_num_p.findall(expre_list[tran_index])
        ran_str_list = ran_str_p.findall(expre_list[tran_index])
        ran_md5_list = md5_p.findall(expre_list[tran_index])
        domain_list = domain_p.findall(expre_list[tran_index])
        ran_num_map = {}
        if len(ran_num_list) != 0:
            ran_num_map = get_rannum(ran_num_list)
        if len(ran_str_list) != 0:
            ran_str_map = get_ranstr(ran_str_list)
            ran_num_map.update(ran_str_map)
        if len(ran_md5_list) != 0:
            ran_md5_map = get_md5(ran_md5_list)
            ran_num_map.update(ran_md5_map)
        
        for index in ran_num_map.keys():
            expre_list[tran_index] = eval(expre_list[tran_index].replace(index, ran_num_map[index]))

        if len(domain_list) != 0:
            ran_dom_map = get_domain(base_url)
            expre_list[tran_index] = ran_dom_map
        
    return expre_list

#解析 pocrule部分
def get_req_infos(rule_list):
    result_list = []
    
    for rule_index in rule_list:
        rule_info ={
                'method':'',
                'path' : '',
                'set':'',
                'body': '',
                'headers' : ''
            }
        for check_info_index in ['method','path','set','body','headers']:
            if check_info_index in rule_index.keys():
                rule_info[check_info_index] = rule_index[check_info_index]
        result_list.append(rule_info)
    return result_list

#根据json和yaml格式，解析单个请求参数
def get_single_poc_infos(yaml_content):
    """
    以fscan的yaml为例，
    set:记录随机值的生成
    rules:记录规则
    groups:记录规则
    detadil:记录poc的详细信息
    """
    #groups和rules一般只有其中一个
    single_poc_info_list = {
        'detail':'',
    }
    if 'set' in yaml_content.keys():
        single_poc_info_list['set'] = yaml_content['set']
    if 'rules' in yaml_content.keys():
        single_poc_info_list['rules'] = []
        for rule_index in yaml_content['rules']:
            single_poc_info_list['rules'].append(rule_index)
    if 'groups' in yaml_content.keys():
        single_poc_info_list['groups'] = []
        for gro_index in yaml_content['groups']:
            single_poc_info_list['groups'].append(yaml_content['groups'][gro_index]) 
    if 'detail' in yaml_content.keys():
        single_poc_info_list['detail'] = yaml_content['detail']
    return single_poc_info_list

#发生http请求
def send_request(method, url, data, hearders, words_set):
    log_file = 'record.txt'
    """
    转换下格式识别format
    """
    if type(words_set) == map:
        for rep_word in [url, data]:
            rep_word = rep_word.replace("{{","@*<")
            rep_word = rep_word.replace("@*<", "{")
            rep_word = rep_word.replace("}}","@*>")
            rep_word = rep_word.replace("@*>", "}")
            rep_word = rep_word.replace("{", "left")
            rep_word = rep_word.replace("}", "right")
            rep_word = rep_word.format(**words_set)
            rep_word = rep_word.replace("left", "{")
            rep_word = rep_word.replace("right", "}")
        for fir_index in hearders:
            for sec_index in fir_index:
                sec_index= sec_index.replace("{{", "@*<")
                sec_index = sec_index.replace("@*<", "{")
                sec_index = sec_index.replace("}}", "@*>")
                sec_index = sec_index.replace("@*>", "}")
                sec_index = sec_index.replace("{", "left")
                sec_index = sec_index.replace("}", "right")
                sec_index = sec_index.format(**words_set)
                sec_index = sec_index.replace("left", "{")
                sec_index = sec_index.replace("right", "}")

    #这里指定目标url地址
    url = base_url + url
    #考虑post、get、delete、head、put、connect、tarce、options
    #connect、tarce、options之后单独补
    if method == "POST":
        try:
            res=requests.post(url=url,data=data.encode(),headers=hearders)
            make_log(log_file, "url:%s send complite. The response code is:%s" % (url, res.status_code))
            return res.status_code,res
        except Exception as e:
            make_log(log_file, "url:%s send failed. Error: %s" % (url, e))
            print(e)
    if method == "GET":
        try:
            res = requests.get(url=url,data=data.encode(), headers=hearders)
            make_log(log_file, "url:%s send complite. The response code is:%s" % (url, res.status_code))
            return res.status_code,res
        except Exception as e:
            make_log(log_file, "url:%s send failed. Error: %s" % (url, e))
            print(e)
    if method == "DELETE":
        try:
            res = requests.delete(url=url, data=data.encode(), headers=hearders)
            make_log(log_file, "url:%s send complite. The response code is:%s" % (url, res.status_code))
            return res.status_code, res
        except Exception as e:
            make_log(log_file, "url:%s send failed. Error: %s" % (url, e))
            print(e)
    if method == "HEAD":
        try:
            res = requests.head(url=url, data=data.encode(), headers=hearders)
            make_log(log_file, "url:%s send complite. The response code is:%s" % (url, res.status_code))
            return res.status_code, res
        except Exception as e:
            make_log(log_file, "url:%s send failed. Error: %s" % (url, e))
            print(e)

    return

#记录日志
def make_log(log_file, log_info):
    with open(log_file,'r+') as f:
        f.write(log_info)
        f.write('\n')

#遍历poc文件夹发送请求
def base_dir_send_poc(poc_dir):
    poc_dir = sorted(os.listdir(poc_dir))
    log_file = "record.txt"
    for poc_file in poc_dir:
        print(poc_file)
        time.sleep(2)   #要等两秒，不然太快了抓包会错乱
        poc_file = os.path.join("pocs", poc_file)
        yaml_content = get_yaml_info(poc_file)
        rule_info = get_single_poc_infos(yaml_content)
        if rule_info.keys().__contains__("set"):
             rule_info["set"] = transform_expression(rule_info["set"])
        for i in ["rules","groups"]:
            if rule_info.__contains__(i):
                if i == "rules":
                    rule_info[i] = get_req_infos(rule_info[i])
                if i == "groups":
                    for sec_index in rule_info[i]:
                        rule_info[i] = get_req_infos(sec_index)
                print(rule_info[i])
                
                #flag标志位，等待tcpdump开启再抓包
                while not(os.path.exists("flag")):
                    count = 1
                
                #遍历yaml里所有的method发送request
                for attack_index in rule_info[i]:
                    if rule_info.keys().__contains__("set"):
                        for index in rule_info[i]:
                            send_request(index['method'], index["path"], index["body"], \
                                     index["headers"], index["set"])
                    else:
                        for index in rule_info[i]:
                            send_request(index['method'], index["path"], index["body"], \
                                        index["headers"], None)
        
        os.system("rm flag")
        os.system("pgrep tcpdump|xargs kill -SIGINT")  #这里结束了tcpdump的进程抓包的脚本会自动开启下一个tcpdump
        
def main():
    #参数指定yml文件目录
    base_dir_send_poc("pocs")

if __name__ == '__main__':
    main()


