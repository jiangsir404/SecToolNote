[TOC]
# awvs 进阶篇 - (二)

## AcuSensor
- Interactive Application Security Testing (IAST) with AcuSensor https://www.acunetix.com/vulnerability-scanner/acusensor-technology/
- How to install the PHP AcuSensor https://www.acunetix.com/support/docs/installing-acusensor-php/

## AcuMonitor
- https://www.acunetix.com/vulnerability-scanner/acumonitor-technology/
常规的Web应用程序测试非常简单-扫描程序将有效载荷发送到目标，接收响应，分析该响应，并基于对该响应的分析引发警报。
但是，某些漏洞在测试过程中未对扫描程序提供任何响应。
在这种情况下，常规的Web应用程序测试无效。

AcuMonitor就是为了检测某些没有回显漏洞的场景下的安全检测。支持检测的漏洞类型如下:
```
Blind Server-side XML/SOAP Injection
Blind XSS (also referred to as Delayed XSS)
Host Header Attack
Out-of-band Remote Code Execution (OOB RCE)
Out-of-band SQL Injection (OOB SQLi)
SMTP Header Injection
Server-side Request Forgery (SSRF)
XML External Entity Injection (XXE)
```


## wvsc
awvs10版本自带的命令行工具是wvs_console.exe, awvs11版本自带的是wvsc.exe, 命令有很大变化，很多命令都隐藏起来了，不细心找很难发现，比如crawl

```
# 常用命令:
//Full Scan
wvsc.exe /scan http://testphp.vulnweb.com /profile Default /log logfile.txt /ls my.lsr /save results.wvs

//xss扫描
wvsc.exe /scan http://testphp.vulnweb.com /profile Xss /status /log logfile.txt /log-level debug

//Crawl扫描
.\wvsc.exe /scan http://testphp.vulnweb.com/AJAX/ /profile empty /status /lo
g d:/tmp/logfile1.txt /log-level debug

参数:
    /scan <URL>, /s <URL>
            Initiate a scan starting with the URL specified
   /profile <scanning profile>, /p <scanning profile>
            The scan profile to use for scanning, 可选值:High_Risk_Alerts,XSS,Weak_Passwords,SQL_Injection,Known_Web_Applications,empty(仅爬虫)
   /status [http://base_url|filename]
            Base URL of the status API. You can specify either a URL or a filename. If no URL or
            filename is specified, the JSON will be written to standard output as a newline separated
            JSON stream
    /log [filename]
            Enable application logging. By default scanner will work without any output to the console.
            If no filename is specified, the standard output will be used for logging
    /log-level <level>
            Minimum log level to appear in logs. Possible values are:
    /settings <filename>
            The settings file to use for this scan. Can be a partial settings XML file with the
            required options set
    /load <filename>
            Load the scan results from the legacy (v10) format. This option can be used to load a
            legacy scan save file and to export it in JSON notification
```

wvs_console.exe的一些命令:
```
>> USAGE: wvs_console /Scan [URL]  OR  /Crawl [URL]  OR  /ScanFromCrawl [FILE]
                      OR  /ScanWSDL [WSDL URL]

>> PARAMETERS                                                                        //参数
       /Scan [URL]               : Scan specified URL                                //扫描指定的URL
       /Crawl [URL]              : Crawl specified URL                               //爬行指定的URL
       /ScanFromCrawl [FILE]     : Scan from crawling results                        //扫描爬行的结果
       /ScanWSDL [WSDL URL]      : Scan web services from WSDL URL                   //扫描来自WSDL的参数URL

       /Profile [PROFILE_NAME]   : Use specified scanning profile during scanning    //使用指定的扫描配置进行扫描
       /Settings [FILE]          : Use specified settings template during scanning   //使用指定的设置模板进行扫描
       /LoginSeq [FILE]          : Use specified login sequence                      //使用指定的登录序列
       /Import [FILE(s)]         : Import files during crawl                         //导入检索的地址进行爬行
       /Run [command line]       : Run this command during crawl                     //爬行时运行这个命令
       /Selenium [FILE]          : Execute selenium script during crawl              //执行selenium脚本进行爬行

       /Save                     : Save scan results                                 //保存结果
       /SaveFolder [DIR]         : Specify the folder were all the saved data will be stored //保存记录的目录
       /GenerateZIP              : Compress all the saved data into a zip file       //对所有的数据进行zip压缩
       /ExportXML                : Exports results as XML                            //将结果以XML方式导出
       /ExportAVDL               : Exports results as AVDL                           //将结果以AVDL方式导出
       /SavetoDatabase           : Save alerts to the database                       //把警告数据保存进数据库
       /SaveLogs                 : Save scan logs                                    //保存扫描日志
       /SaveCrawlerData          : Save crawler data (.CWL file)                     //保存爬行数据
       /GenerateReport           : Generate a report after the scan was completed    //扫描完成后生成报告
       /ReportFormat [FORMAT]    : Generated report format (REP, PDF, RTF, HTML)     //生成报告的格式
       /ReportTemplate [TEMPLATE]: Specify the report template                       //特定的报告模板

```

## awvsapi
- awvs11 api文档: https://github.com/h4rdy/Acunetix11-API-Documentation
- 官方api相关信息 https://www.acunetix.com/?s=api

awvs11版本开始后提供扫描api(需要破解版本才能申请api), api文档需要正式的licence-key才能在[官方下载](https://www.acunetix.com/support/api-documentation/)，目前github有提供一份awvs11的非正式官方文档.

awvs主要分为五个接口

1. Dashboard接口: /api/v1/me/

2 . Targets接口 /api/v1/targets
```
a). General设置 
b). Crawl设置
c). HTTP设置
d). Advanced设置
```
3 . Scans接口

4 . Vulnerabilities接口

5 . Reports接口

awvs11/12和awvs13的api差异
```
1. 获取扫描结果和漏洞信息的差异。

awvs11/12中的接口有如下几个
//获取扫描概况信息
Method:GET
URL: /api/v1/scans/{scan_id}/results/{scan_session_id}/statistics
//获取扫描漏洞结果
Method:GET
URL: /api/v1/scans/{scan_id}/results/{scan_session_id}/vulnerabilities
//获取父节点为2(跟目录)的爬虫结果信息
https://localhost:3443/api/v1/me/manual_intervention/bb435e6fe2c0c7090627da5097fb3c72

awvs13的接口如下:
/scans/db898022-bda4-4a98-a1a7-50ca48cdfbf0/info

```