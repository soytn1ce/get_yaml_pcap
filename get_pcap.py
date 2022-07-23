#encoding:utf-8
import os

#这里注意两个地方的文件一定要排序，不然名字和pcap对不上
poc_list=sorted(os.listdir("pocs"))
for poc_file in poc_list:
    f=open("flag","w+")
    f.close()
    #这里抓包条件自己指定,tcpdump会被attack自动关闭开启下一个文件
    os.system("tcpdump port 80 -i eth0 -w pcap1/%s.pcap" % poc_file)  

