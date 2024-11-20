import json
import time
import uuid
from datetime import datetime
import requests
from collections import defaultdict
import os
import random
import base64
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

def get_file_content(file_path):
    file_content = ''
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content.strip()

def get_auth_info(cookie_content, user_agent):
    request_url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/helper/helper_upload_params"

    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/post/list',
        "User-Agent": user_agent,
        "Cookie": cookie_content
    }

    response = requests.post(request_url, headers=headers)
    jsonObj = response.json()
    if jsonObj['errCode'] != 0:
        print(response.text)
        return None
    return jsonObj['data']


def get_video_list(cookie_content, user_agent, auth_info):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/post/post_list"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "pageSize": 20,
        "currentPage": 1,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/post/list',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)

    video_list = jsonObj['data']['list']
    result = []
    for video in video_list:
        ele = {}
        ele['title'] = video['desc']['description']
        readable_time = datetime.fromtimestamp(video['createTime'])
        readable_str = readable_time.strftime('%Y-%m-%d %H:%M:%S')
        ele['createTime'] = readable_str
        ele['exportId'] = video['exportId']
        result.append(ele)

    return result

def get_comment_list(cookie_content, user_agent, auth_info, export_id):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/comment/comment_list"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "lastBuff": "",
        "exportId": export_id,
        "commentSelection": False,
        "forMcn": False,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/comment',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.request("POST", url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)
    comment_list = jsonObj['data']['comment']
    if len(comment_list) > 0:
        print(json.dumps(jsonObj, indent=4, ensure_ascii=False))
    return comment_list


def publish_comment(cookie_content, user_agent, auth_info, export_id, comment_text, root_comment_id, reply_comment_info):
    request_url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/comment/create_comment"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "replyCommentId": reply_comment_info['commentId'] if "commentId" in reply_comment_info else "",
        "content": comment_text,
        "clientId": str(uuid.uuid4()),
        "rootCommentId": root_comment_id,
        "comment": reply_comment_info,
        "exportId": export_id,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/comment',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(request_url, headers=headers, data=json_str)

def random_comment_text():
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
    print("formatted_time: \n", formatted_time)

    comment_text = f"这是王世兵的测试评论 {formatted_time}" + " 🤣"
    return comment_text

def random_private_msg_text():
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
    print("formatted_time: \n", formatted_time)

    comment_text = f"{formatted_time} 代码自动化生成：\n住建部部长倪虹：将通过货币化安置房方式新增实施100万套城中村改造、危旧房改造 🙂"
    return comment_text

def delete_comment(cookie_content, user_agent, auth_info, export_id, comment_id):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/comment/del_comment"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "exportId": export_id,
        "commentId": comment_id,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/comment',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }
    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)

    print("delete_comment: \n", response.text)


def test_comment(cookie_content, user_agent, auth_info):
    video_list = get_video_list(cookie_content, user_agent, auth_info)

    # 遍历每个视频，给每个视频添加评论
    for video_item in video_list:
        export_id = video_item['exportId']
        comment_list = get_comment_list(cookie_content, user_agent, auth_info, export_id)

        # 挑一个根级评论，对其进行回复
        comment_text = random_comment_text()
        if len(comment_list) > 0:
            comment_item = comment_list[0]
            root_comment_id = comment_item['commentId']
            reply_comment_info = comment_item
            publish_comment(cookie_content, user_agent, auth_info, export_id, comment_text, root_comment_id,
                           reply_comment_info)

            # 挑一个二级评论(如果有)，对其进行回复
            comment_text = random_comment_text()
            comment_item = comment_list[0]
            root_comment_id = comment_item['commentId']
            level_two_comment = comment_item['levelTwoComment']
            if len(level_two_comment) > 0:
                reply_comment_info = level_two_comment[0]
                publish_comment(cookie_content, user_agent, auth_info, export_id, comment_text, root_comment_id,
                               reply_comment_info)

        # 生成根级评论
        comment_text = random_comment_text()
        publish_comment(cookie_content, user_agent, auth_info, export_id, comment_text, "", {})


    # 遍历每个视频，模拟删除视频里的一条评论
    for video_item in video_list:
        export_id = video_item['exportId']
        comment_list = get_comment_list(cookie_content, user_agent, auth_info, export_id)
        if len(comment_list) > 0:
            comment_item = random.choice(comment_list)
            comment_id = comment_item['commentId']
            delete_comment(cookie_content, user_agent, auth_info, export_id, comment_id)

def get_user_name(cookie_content, user_agent, auth_info):
    request_url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/get-finder-username"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(request_url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)
    username = jsonObj['data']['finderUsername']
    return username

def get_private_msg_history(cookie_content, user_agent, auth_info):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/get-history-msg"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)
    return jsonObj['data']['msg']

def get_private_msg_session_info(cookie_content, user_agent, auth_info, session_id_list):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/get-session-info"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "sessionId": session_id_list,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)
    session_info = jsonObj['data']['sessionInfo']
    session_map = {}
    for session_item in session_info:
        session_map[session_item['sessionId']] = session_item
    return session_map

def get_media_info(cookie_content, user_agent, auth_info, raw_content, img_msg):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/get-media-info"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "mediaType": 3,
        "imgMsg": img_msg,
        "rawContent": raw_content,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }

    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    jsonObj = json.loads(response.text)
    return jsonObj['data']['imgContent']


def send_private_msg_text(cookie_content, user_agent, auth_info, session_id, me_user_name, to_user_name, msg_content):
    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/send-private-msg"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "msgPack": {
            "sessionId": session_id,
            "fromUsername": me_user_name,
            "toUsername": to_user_name,
            "msgType": 1,
            "textMsg": {
                "content": msg_content
            },
            "cliMsgId": str(uuid.uuid4())
        },
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }
    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    print(response.status_code)
    print(response.text)


def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16).encode()


def unpad(s):
    return s[0:-ord(s[len(s) - 1:])]


def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = hashlib.md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = hashlib.md5(key + data).digest()
        final_key += key
    return final_key[:output]


def encrypt(data, passphrase):
    data = bytes(data, 'utf-8')
    passphrase = bytes(passphrase, 'utf-8')
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipherbyte = base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(data)))
    return cipherbyte

def calc_file_md5(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()

    decoded_data = binary_data.decode('latin1')
    encoded_data = decoded_data.encode('utf-8')

    md5_hash = hashlib.md5(encoded_data).hexdigest()
    print(f'MD5: {md5_hash}')
    return md5_hash

def file_to_base64(file_path):
    # 以二进制模式读取文件
    with open(file_path, "rb") as file:
        file_content = file.read()  # 读取文件内容
        # 将文件内容进行 Base64 编码
        base64_encoded = base64.b64encode(file_content)
        # 将字节类型的编码结果转换为字符串
        return base64_encoded.decode('utf-8')

def upload_media_info(cookie_content, user_agent, auth_info, session_id, me_user_name, to_user_name, img_path):
    file_name = os.path.basename(img_path)
    aes_key = encrypt(file_name, file_name)
    aes_key = aes_key.decode('utf-8')
    file_md5 = calc_file_md5(img_path)
    file_size = os.path.getsize(img_path)
    file_base64 = file_to_base64(img_path)

    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/upload-media-info"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "content": "data:application/octet-stream;base64," + file_base64,
        "chunk": 0,
        "chunks": 1,
        "fromUsername": me_user_name,
        "toUsername": to_user_name,
        "aesKey": aes_key,
        "mediaSize": file_size,
        "mediaType": 3,
        "md5": file_md5,
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }
    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    print(response.status_code)
    print(response.text)
    jsonObj = json.loads(response.text)
    return jsonObj['data']['imgMsg']


def send_private_msg_image(cookie_content, user_agent, auth_info, session_id, me_user_name, to_user_name, img_path):
    # 图片上传
    img_msg = upload_media_info(cookie_content, user_agent, auth_info, session_id, me_user_name, to_user_name, img_path)

    url = "https://channels.weixin.qq.com/cgi-bin/mmfinderassistant-bin/private-msg/send-private-msg"

    uin = auth_info['uin']
    timestamp_ms = int(time.time() * 1000)
    request_data = {
        "msgPack": {
            "sessionId": session_id,
            "fromUsername": me_user_name,
            "toUsername": to_user_name,
            "msgType": 3,
            "imgMsg": img_msg,
            "cliMsgId": str(uuid.uuid4())
        },
        "timestamp": str(timestamp_ms),
        "rawKeyBuff": None,
        "pluginSessionId": None,
        "scene": 7,
        "reqScene": 7
    }
    headers = {
        'Origin': 'https://channels.weixin.qq.com',
        'Referer': 'https://channels.weixin.qq.com/platform/private_msg',
        'User-Agent': user_agent,
        'X-WECHAT-UIN': str(uin),
        'Cookie': cookie_content,
        'Content-Type': 'application/json'
    }
    json_str = json.dumps(request_data, separators=(',', ':'), ensure_ascii=False)
    response = requests.post(url, headers=headers, data=json_str)
    print(response.status_code)
    print(response.text)

def test_private_message(cookie_content, user_agent, auth_info):
    username = get_user_name(cookie_content, user_agent, auth_info)
    print("username: \n", username)

    msg_list = get_private_msg_history(cookie_content, user_agent, auth_info)

    # 搜集所有的session_id并去重
    session_id_set = set()
    for msg_item in msg_list:
        session_id_set.add(msg_item['sessionId'])

    # 批量获取session的信息
    session_map = get_private_msg_session_info(cookie_content, user_agent, auth_info, list(session_id_set))

    grouped_data = defaultdict(list)
    for item in msg_list:
        session_id = item['sessionId']
        grouped_data[session_id].append(item)

    msg_group_list = list(grouped_data.values())

    for msg_group in msg_group_list:
        sorted_msg_group = sorted(msg_group, key=lambda x: x['seq'])

        # 打印聊天对象的信息
        msg_item = sorted_msg_group[0]
        session_id = msg_item['sessionId']
        session_info = session_map[session_id]

        session_nick_name = session_info['nickname']
        session_nick_avatar = session_info['headImgUrl']
        session_user_name = session_info['username']
        session_type = msg_item['sessionType']  # 2:陌生人打招呼；3:熟人私信
        print(f"\n\n----------------- {session_nick_name} -----------------")

        for msg_item in sorted_msg_group:
            session_id = msg_item['sessionId']
            session_info = session_map[session_id]

            session_nick_name = session_info['nickname']
            session_nick_avatar = session_info['headImgUrl']
            session_user_name = session_info['username']

            from_user_name = msg_item['fromUsername']
            to_user_name = msg_item['toUsername']

            show_from_user_name = "我"
            if from_user_name == session_user_name:
                show_from_user_name = session_nick_name

            show_to_user_name = "我"
            if to_user_name == session_user_name:
                show_to_user_name = session_nick_name

            dt_object = datetime.fromtimestamp(msg_item['ts'])
            readable_date = dt_object.strftime('%Y-%m-%d %H:%M:%S')

            seq = msg_item['seq']
            session_type = msg_item['sessionType'] # 2:陌生人打招呼；3:熟人私信
            msg_type = msg_item['msgType']
            if msg_type == 1:
                # 纯文本（含内置表情）
                content = msg_item['textMsg']['content']
                print(f"{readable_date} {show_from_user_name} 对 {show_to_user_name} 说: {content}")
            elif msg_type == 3:
                # 图片
                img_base64_str = get_media_info(cookie_content, user_agent, auth_info, msg_item['rawContent'], msg_item['imgMsg'])
                image_data = base64.b64decode(img_base64_str)
                img_name = f"output/output_image_{seq}.png"
                with open(img_name, "wb") as f:
                    f.write(image_data)
                # os.system("open " + img_name)
                show_img_base64_str = img_base64_str[0:15] + "..."
                print(f"{readable_date} {show_from_user_name} 对 {show_to_user_name} 说: {show_img_base64_str}")
            else:
                print(f"{readable_date} {show_from_user_name} 对 {show_to_user_name} 说: {msg_item['rawContent']}")

        # 测试发条私信---发纯文本
        if session_type == 3 or session_type == 2:
            send_private_msg_text(cookie_content, user_agent, auth_info, session_id, username, session_user_name, random_private_msg_text())
        # 测试发条私信---发图片
        if session_type == 3 or session_type == 2:
            img_path = "data/img.png"
            send_private_msg_image(cookie_content, user_agent, auth_info, session_id, username, session_user_name, img_path)


if __name__ == '__main__':
    cookie_content = get_file_content("shipinhao_cookie.txt")
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"

    auth_info = get_auth_info(cookie_content, user_agent)

    # 测试评论
    # test_comment(cookie_content, user_agent, auth_info)

    # 测试私信
    test_private_message(cookie_content, user_agent, auth_info)


