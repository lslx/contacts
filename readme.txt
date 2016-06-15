18:16 2016/6/15

不能收取gmail的bug的调试笔记

问题描述：
真实环境中firefox环境下，不能收取邮件。（gmail已登录）。

真实环境的firefox版本： 43.0.1
现已将真实环境版本下载到本地：G:\dev_code_x\contacts\Release\Mozilla Firefox


浏览器，cookie，以及程序规则：
firefox cookie文件位置 C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\eq78rmhd.default\cookies.sqlite
chrome cookie文件位置   "C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Cookies"

cookie 由多字段组成， 不同的登录状态，数据库中有不同数目的字段（主机，名字，值）
未登录（或已登出）gg时有一些字段，登录gg后增加了一些字段，进入gmail后，又增加一些字段。

不同浏览器，如chrome和ff，在不同登录状态记录的cookie应当是一致的（但它们分别记录），（也可能不一致，需验证），而gmail获取程序记录cookie
是集中的，来源于多个浏览器， 可能导致cookie混杂，（可能是这个问题导致的，某些时候不能获取gmail）

已知的经验：
当已未登录gmail，不能获取gmail，即使数据库中有一些cookie项， 即使登录gg，而未进入gmail仍然如此，此问题应该可修正。


20:33 2016/6/15
已经将cookie分开存储，获取，发送。发送后确认有效cookie用于下次请求，自测已完成
