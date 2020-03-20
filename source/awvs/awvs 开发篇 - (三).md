[TOC]

# awvs 开发篇 - (三)

Referer: 
- https://github.com/fnmsd/awvs_script_decode
- awvs: https://github.com/grayddq/PublicSecScan
- 编写自己的Acunetix WVS漏洞脚本 – 乌帽子 http://www.vuln.cn/7046
- 对AWVS一次简单分析 https://paper.seebug.org/461/

## 脚本规则
```
Network：此目录下的脚本文件是当扫描器完成了端口扫描模块后执行，这些脚本可以检测TCP端口的开放情况，比如检测FTP的21端口是否开放、是否允许匿名登录； 
PerFile：此目录下的脚本是当扫描器爬虫爬到文件后执行，比如你可以检查当前测试文件是否存在备份文件，当前测试文件的内容等； 
PerFolder：此目录下的脚本是当扫描器爬虫爬行到目录后执行，比如你可以检测当前测试目录是否存在列目录漏洞等； 
PerScheme：此目录下的脚本会对每个URL的 GET、POST结构的参数进行检测，AWVS定义了的参数包括HTTP头、Cookies、GET/POST参数、文件上传(multipart/form-data)……比如你可以检测XSS、SQL注入和其他的应用程序测试； 
PerServer：此目录下的脚本只在扫描开始是执行一次，比如你可以检测Web服务器中间件类型； 
PostScan：此目录下的脚本只在扫描结束后执行一次，比如你可以检测存储型XSS、存储型SQL注入、存储型文件包含、存储型目录遍历、存储型代码执行、存储型文件篡改、存储型php代码执行等； 
XML：漏洞的详细描述文档都在这里。 
```