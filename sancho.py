import requests
from bs4 import BeautifulSoup
import yaml
import time
import os 
import argparse

headers = {
'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:65.0) Gecko/20100101 Firefox/65.0'
}

def read_file_text(file : str, mode : str) -> list:
    file_stream = open(file,mode,encoding='utf-8')
    text_list = []
    text = file_stream.readline()
    while(text):
        text_list.append(text.strip().replace('\n', ''))
        text = file_stream.readline()
    file_stream.close()
    return text_list

# 读取yaml 文件为 dict 形式
def read_yaml_text(file : str, mode : str) -> dict:
    feature_text = open(file,'r',encoding='utf-8')
    text = feature_text.read()
    feature_dict = yaml.load(text,Loader=yaml.FullLoader)
    feature_text.close()
    return feature_dict

def write_file_text(file : str,message: str):
    file_base = "C:/Users/61476/Desktop/code/" + file + ".txt"
    file_stream = open(file_base, 'a', encoding='utf-8')
    file_stream.write(message+"\n")
    file_stream.close()

def get_alert_list(cve : str) -> list:
    try:
        alert_list=[]
        url = "https://avd.aliyun.com/detail?id={}".format(cve)
        print(url + "正在爬取中")
        html = requests.get(url, verify=False,headers=headers).text 
        
        if "未收录" in html:
            print(cve+": 该漏洞尚未被收录")
        else:
            alert_list = parse_text(html)
        return alert_list
    except Exception as e:
        print("An error occurred:", e)
        return []

# 解析文本获取所有有关告警的信息
def parse_text(html : str) -> list:
    
    alert_list = []
    #print(html)
    bs = BeautifulSoup(html, 'html.parser')

    # 获得阿里云漏洞库对该漏洞的标签标注
    final_text= bs.find('div', attrs={"class":"vuln-sidebar-offset"}).find_all('div', attrs={"class":"card card--sidebar"})[1].tbody
    if final_text.find_all(name="tr"):
        for i in final_text.find_all(name="tr"):
            alert = i.find_all(name="td")
            alert_list.append(alert[1].text.strip())
    else:
        print(cve+"阿里云没有给出的漏洞类型标签")

    # 获取阿里云漏洞库中针对该漏洞的标题
    title_text = bs.find('span',attrs={"class":"header__title__text"}).text.strip()
    alert_list.append(title_text)

    # 获取阿里云漏洞库中针对该漏洞的内容详情
    introduce_text = bs.find_all('div',attrs={"class":"text-detail pt-2 pb-4"})[0]
    for div_text in introduce_text.find_all(name="div"):
        alert_list.append(div_text.text.strip())
    #alert_list.append(introduce_text)
    
    return alert_list

# 给定某漏洞获取得到的相关漏洞介绍，判断该漏洞都属于什么漏洞
def get_classification(alert_list:list, feature_dict:dict) -> list:
    # classification = []
    classification_list = []
    for alert in alert_list:
        # 遍历所有种类的漏洞
        for classification,features in feature_dict.items():
            # 遍历某种类型漏洞的所有键值
            for feature in features:
                # 判断键值是否存在于alert
                if feature in alert:
                    classification_list.append(classification)
                    break
                
    return list(set(classification_list))

def get_all_feature(cve_list:list,feature_dict:dict):
    # print(feature_dict)
    alert_list = []
    for cve in cve_list:
        
        alert_list = get_alert_list(cve)
        print(alert_list)
        if(len(alert_list) !=0):
            classification_list  = get_classification(alert_list,feature_dict)
            if len(classification_list) != 0 :
                for classification in classification_list:
                    write_file_text(classification,cve)
            else:
                print(cve+"其他漏洞")
                write_file_text("其他漏洞",cve)

def get_only_feature(cve : str,feature_dict:dict):
    alert_list = get_alert_list(cve)
    print(alert_list)
    if(len(alert_list) !=0):
        classification_list  = get_classification(alert_list,feature_dict)
        if len(classification_list) != 0 :
            for classification in classification_list:
                print(cve+"属于:" + classification + "漏洞")
        else:
            print(cve+"其他漏洞")

if __name__ == "__main__":
# print(total_dict)
    cur_path = os.path.dirname(os.path.realpath(__file__))

    parser = argparse.ArgumentParser(description=  "-f 指定一个分类的标签文件 -t 批量的获取CVE漏洞的分类 -o 获取单个CVE漏洞的分类")
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-f", "--feature", help="分类的标签文件")
    group.add_argument("-t", "--total", help="待处理的cve编号文件.\n eg.\n python sancho.py -t cve.txt -f feature.yaml")
    group.add_argument("-o", "--only", help="单个cve编号\n eg.\n python ancho.py -o CVE-2011-243 -f feature.yaml")
    # parser.add_argument("-H", "--custom-help", action="help", help="显示帮助文档")
    args = parser.parse_args()
   
    feature = args.feature
    cve_list = args.total
    cve_id = args.only
   
    if not feature or ( not cve_list and not cve_id):
        parser.error("需要同时提供 -f/--feature 和 -t/--total 或 -o/--only 参数之一")
    elif cve_id:
        feature_file = os.path.join(cur_path, feature)
        
        feature_dict = read_yaml_text(feature_file,'r')

        get_only_feature(cve_id,feature_dict)
    else:
        cve_file = os.path.join(cur_path, cve_list)
        feature_file = os.path.join(cur_path, feature)

        cve_list = read_file_text(cve_file,'r')
        feature_dict = read_yaml_text(feature_file,'r')
        
        get_all_feature(cve_list,feature_dict)