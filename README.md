# sancho
自定义某一类型漏洞的特征、指纹。可以批量判断CVE是否属于该类别

通过爬取阿里云漏洞库关于该漏洞的描述。
形如这样，针对每种漏洞，选取文本特征，从而获得分类。
```
cmd:
  - 注入
  - 执行
  - 命令
overflow:
  - 溢出
  - 堆栈
  - overflow
sql:
  - sql注入
  - SQL注入
unauth:
  - 未授权
travel:
  - 路径穿越
  - 路径遍历
  - ..
Information:
  - 信息泄露
  - 信息暴露
```
