## 飞扬路由器认证程序

**此工具仅适用于武汉地区的电信飞扬校园网**

程序有以下特点

1. 可以突破共享限制,使任何路由器使用校园网,测试过十几块钱的二手TPlink 和 250的红米AX3000 WiFi6均无问题
2. 因为使用手机端协议,所以现在闲时(路由器没有人链接)的时候,会被校园网踢下线,你可以在宿舍丢一台电脑保持WiFi一直链接路由器,或者使用openwrt固件的路由器编写一个定时ping脚本
3. 需要自己抓包拿到当天的登陆密码 填入config.ini对应的日期中 ,你可以添加我的机器人 842446224 计算当天的密码 **发送/fy触发指令**
4. 可以避免花200多块钱买成本40左右的K2路由器,节省成本,自由挑选自己想要的路由器
5. 在登陆的关键操作附近 写了比较详细的注释

![image-20220905120234052](http://bucket.dongxiaohao.top/image-20220905120234052.png)

![image-20220905120103731](http://bucket.dongxiaohao.top/image-20220905120103731.png)





## 关于校园网的认证流程可以参考我的这篇博客

[Feiyoung校园网的手机端认证原理分析 – Dongxiaohao](https://dongxiaohao.top/2021/11/19/feiyoung校园网的手机端认证原理分析/)

#### 使用方式

1. 在config中填好自己的手机号
2. 向机器人发送自己的校园网密码,将加密后的密码 填入config中对应的日期中
3. 连接路由器/校园网 运行程序 即可



#### 写在后面

为了稍微长久一点的使用,暂不贴出算法,只放出一个机器人算号工具,

其余大佬也公布过算法可以自行研究实现

由于本人已经毕业工作了了,曾经为了对抗校园网也熬了很多个夜,

现在武汉地区的各大高校陆陆续续的修改成了光纤入户

也修改了认证方式,不知道这个项目还能适用多久



Tips:假如您没有编码基础,你也可以使用编译好的桌面版本

[点击下载](https://wwm.lanzoub.com/iZU3T0b53mqd)