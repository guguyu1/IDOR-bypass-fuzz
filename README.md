# IDOR-bypass-fuzz
IDOR bypass fuzz 权限绕过burp 插件 fuzz （shiro 等）

具体实现：获取所有code:200请求, 全部去掉cookie进行请求, 返回码除了200，400，503，500,全部进行IDOR fuzz测试,出现返回code:200输出payload。

![image](https://user-images.githubusercontent.com/50195525/131288882-17babc23-4c79-49bb-a6f8-63ed6aa7b86b.png)

在shiro权限绕过的基础上，又添加了一下fuzz payload, fuzz一下更健康。

![image](https://user-images.githubusercontent.com/50195525/131289016-194b9b5f-ca3d-42a7-b244-5c4b70fcbcf5.png)



在https://github.com/sting8k/BurpSuite_403Bypasser 基础上进行的更改。
