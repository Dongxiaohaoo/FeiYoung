#!
import sys, requests, configparser, time, json
import traceback
from xml.etree import ElementTree
from urllib import parse


def load_config():
    config = configparser.ConfigParser()
    today = time.strftime('%d', time.localtime(time.time()))
    config.read('config.ini', encoding='utf-8')
    phone = config['config']['phone']
    pwd = config['config']['pwd']
    json_pwd = json.loads(pwd)
    login_pwd = json_pwd['day' + today]
    if login_pwd == "":
        input(str(today) + "号的登陆密码尚未配置")
        return
    # 执行登陆操作
    do_login(phone, login_pwd)


def do_login(phone: str, pwd: str) -> None:
    '''
    认证主方法
    :param phone: 手机号
    :param pwd:   密码
    :return:
    '''
    url = 'http://www.baidu.com/'
    print('-----------------------------------')
    try:
        redirect_url = requests.get(url, timeout=10).url
    except:
        input('重定向失败,请检查本机DNS是否设置为自动,并确认网络是否正常。')
        return
    if len(url) == len(redirect_url):
        input('当前设备已经链接互联网')
        return

    redirect_url_parse = parse.parse_qs(parse.urlparse(redirect_url).query)

    # 获取此次重定向的100.64的内网地址
    user_ip = redirect_url_parse['userip']

    # 获取需要登陆的设备MAC地址
    user_mac = redirect_url_parse['usermac']

    # 获取认证服务器的IP地址
    nas_ip = redirect_url_parse['nasip']

    # post请求飞扬地址 获取响应的xml最终登陆内容
    header = {
        'User-Agent': 'CDMA+WLAN(Maod)',
        'Host': '58.53.199.144:8001',
        'Connection': 'Keep - Alive',
        'Accept - Encoding': 'gzip'
    }
    url = 'http://58.53.199.144:8001'
    data = {
        'userip': user_ip,
        'wlanacname': '',
        'nasip': nas_ip,
        'usermac': user_mac,
        'aidcauthtype': '0'
    }
    response_login_info_xml = requests.post(url, headers=header, data=data)
    # 获得最终URL地址,登录POST URL
    StrResponse = response_login_info_xml.text

    ResponseData = ElementTree.XML(StrResponse.encode('utf-8').decode('utf-8'))
    # 获得认证的URL
    url2 = ResponseData.find('Redirect').find('LoginURL').text
    data1 = {
        "UserName": "!^Adcm0" + phone,
        "Password": pwd,
        "AidcAuthAttr1": ResponseData.find('Redirect').find('AidcAuthAttr1').text,  # 获取当前时间
        "AidcAuthAttr3": "KQSNcAp2",
        "AidcAuthAttr4": "V0TYDlQ73yQEPWkxCGym4Ls=",
        "AidcAuthAttr5": "KRiKcAhgnDF+RGoxCHKr5aQS46ZrjX3VVRrp1+4oKIWqNs3sVMBk3lz2zk+txME=",
        "AidcAuthAttr6": "KW+HbX107y91Rm47C2yn4bs=",
        "AidcAuthAttr7": "",
        "AidcAuthAttr8": "",
        "AidcAuthAttr15": "KR2ObQw=",
        "AidcAuthAttr22": "KA==",
        "AidcAuthAttr23": "a1/ePV093w==",
        "createAuthorFlag": "0"
    }
    login_info = requests.post(url2, data=data1, headers=header).text

    ResponseData2 = ElementTree.XML(login_info.encode('utf-8').decode('utf-8'))
    # 打印认证信息
    print('--------------登陆状态---------------------')
    print(ResponseData2.find('AuthenticationReply').find('ReplyMessage').text)
    input('------------------------------------------')


if __name__ == '__main__':
    try:
        load_config()
    except Exception as e:
        traceback.print_exc()
        input("出现如下异常:%s" % e)
