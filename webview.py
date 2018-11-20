# coding:utf-8
import os
import struct
import base64
import hashlib
import socket
import threading
import paramiko


def get_ssh(ip, user, pwd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 22, user, pwd, timeout=15)
        return ssh
    except Exception as e:
        print(e)
        return "False"


def recv_data(conn):  # 服务器解析浏览器发送的信息
    try:
        all_data = conn.recv(1024)
        if not len(all_data):
            return False
    except:
        pass
    else:
        code_len = ord(all_data[1]) & 127
        if code_len == 126:
            masks = all_data[4:8]
            data = all_data[8:]
        elif code_len == 127:
            masks = all_data[10:14]
            data = all_data[14:]
        else:
            masks = all_data[2:6]
            data = all_data[6:]
        raw_str = ""
        i = 0
        for d in data:
            raw_str += chr(ord(d) ^ ord(masks[i % 4]))
            i += 1
        return raw_str


def send_data(conn, data):  # 服务器处理发送给浏览器的信息
    if data:
        data = str(data)
    else:
        return False
    token = "\x81"
    length = len(data)
    if length < 126:
        token += struct.pack("B", length)  # struct为Python中处理二进制数的模块，二进制流为C，或网络流的形式。
    elif length <= 0xFFFF:
        token += struct.pack("!BH", 126, length)
    else:
        token += struct.pack("!BQ", 127, length)
    data = '%s%s' % (token, data)
    conn.send(data)
    return True


def handshake(conn, address, thread_name):
    headers = {}
    shake = conn.recv(1024)
    if not len(shake):
        return False

    print('%s : Socket start handshaken with %s:%s' % (thread_name, address[0], address[1]))
    header, data = shake.split('\r\n\r\n', 1)
    for line in header.split('\r\n')[1:]:
        key, value = line.split(': ', 1)
        headers[key] = value

    if 'Sec-WebSocket-Key' not in headers:
        print('%s : This socket is not websocket, client close.' % thread_name)
        conn.close()
        return False

    MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    HANDSHAKE_STRING = "HTTP/1.1 101 Switching Protocols\r\n" \
                       "Upgrade:websocket\r\n" \
                       "Connection: Upgrade\r\n" \
                       "Sec-WebSocket-Accept: {1}\r\n" \
                       "WebSocket-Origin: {2}\r\n" \
                       "WebSocket-Location: ws://{3}/\r\n\r\n"

    sec_key = headers['Sec-WebSocket-Key']
    res_key = base64.b64encode(hashlib.sha1(sec_key + MAGIC_STRING).digest())
    str_handshake = HANDSHAKE_STRING.replace('{1}', res_key).replace('{2}', headers['Origin']).replace('{3}',
                                                                                                       headers['Host'])
    conn.send(str_handshake)
    print('%s : Socket handshaken with %s:%s success' % (thread_name, address[0], address[1]))
    print('Start transmitting data...')
    print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')
    return True


def dojob(conn, address, thread_name):
    handshake(conn, address, thread_name)  # 握手
    conn.setblocking(0)  # 设置socket为非阻塞

    ssh = get_ssh("101.89.211.155", "root", "Bespin@shanghai")   # 连接远程服务器
    ssh_t = ssh.get_transport()
    chan = ssh_t.open_session()
    chan.setblocking(0)  # 设置非阻塞
    chan.exec_command('tail -f /var/log/messages')

    while True:
        clientdata = recv_data(conn)
        if clientdata is not None and 'quit' in clientdata:  # 但浏览器点击stop按钮或close按钮时，断开连接
            print('%s : Socket close with %s:%s' % (thread_name, address[0], address[1]))
            send_data(conn, 'close connect')
            conn.close()
            break
        while True:
            while chan.recv_ready():
                clientdata1 = recv_data(conn)
                if clientdata1 is not None and 'quit' in clientdata1:
                    print('%s : Socket close with %s:%s' % (thread_name, address[0], address[1]))
                    send_data(conn, 'close connect')
                    conn.close()
                    break
                log_msg = chan.recv(10000).strip()  # 接收日志信息
                print(log_msg)
                send_data(conn, log_msg)
            if chan.exit_status_ready():
                break
            clientdata2 = recv_data(conn)
            if clientdata2 is not None and 'quit' in clientdata2:
                print('%s : Socket close with %s:%s' % (thread_name, address[0], address[1]))
                send_data(conn, 'close connect')
                conn.close()
                break
        break


def ws_service():
    index = 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 12344))
    sock.listen(100)

    print('\r\n\r\nWebsocket server start, wait for connect!')
    print('- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -')
    while True:
        connection, address = sock.accept()
        thread_name = 'thread_%s' % index
        print('%s : Connection from %s:%s' % (thread_name, address[0], address[1]))
        t = threading.Thread(target=dojob, args=(connection, address, thread_name))
        t.start()
        index += 1


ws_service()
