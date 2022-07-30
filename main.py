"""
Email Code Receiving Utility
CMDS:
    login: Input email info and send test file
        as <Name>: login as saved info
    del <Name>: delete info
    exit: exit
    recv: receive email
        last <Number>: Select Code from last <Number>
    help: list above
"""
import email
import getpass
import os
import poplib
import re
import shelve
import socket
from email.parser import Parser
from email.utils import parseaddr
from pyperclip import copy

def cmdline(prt=""):
    if not prt == '':
        prt = "\033[94m(" + prt + ") RecvCode>\033[0m"
    else:
        prt = "\033[93mRecvCode>\033[0m"
    print(prt, end=' ')
    command = input().strip()
    try:
        while command[-1] == '\\':
            print('...>', end=' ')
            command = command[:-1] + input().strip()
    except IndexError:
        pass
    return command


def getinfo():
    email_name = input("Email: ")
    password = getpass.getpass("Password (not prompted): ")
    pop = input("POP server: ")
    save_as = input("Save as: ").strip()
    return {
        "email": email_name,
        "password": password,
        "server": pop,
        "save_as": save_as
    }


def get_content(server: poplib.POP3, index):
    resp, lines, octets = server.retr(index)
    msg_content = b'\r\n'.join(lines).decode('utf-8')
    msg = Parser().parsestr(msg_content)
    sender = parseaddr(msg.get('from'))[1]

    def inside_func(message: email.message.Message):
        res = bytes()
        if message.is_multipart():
            for one in message.get_payload():
                res += inside_func(one)
        else:
            if message.get_content_type() in ('text/plain', 'text/html'):
                res = message.get_payload().encode()
            else:
                res = '\r\n$ATTACHMENT$\r\n'.encode()
        return res

    msg_str = inside_func(msg)
    return msg_str.decode(), sender


if __name__ == '__main__':
    if not os.path.exists('data'):
        os.mkdir('data')
    if not os.path.isdir('data'):
        os.remove('data')
        os.mkdir('data')
    user = ''
    user_prof = {}
    server = None
    c = list()
    while True:
        data = shelve.open("data/data")
        try:
            cmd = cmdline(user)
            args = cmd.split(' ')
            if args[0] == 'exit':
                break
            elif args[0] == 'login':
                if len(args) >= 2:
                    if args[1] == 'as':
                        if len(args) == 3:
                            prof = args[2]
                            try:
                                user_prof = data[prof]
                            except KeyError:
                                print('\033[91m  No profile found.\033[0m')
                                continue
                            try:
                                server = poplib.POP3(user_prof['server'])
                                server.user(user_prof['email'])
                                server.pass_(user_prof['password'])
                            except poplib.error_proto:
                                try:
                                    server = poplib.POP3_SSL(user_prof['server'])
                                    server.user(user_prof['email'])
                                    server.pass_(user_prof['password'])
                                except poplib.error_proto:
                                    print('\033[91m  Error while logging in.\033[0m')
                                    continue
                            except socket.gaierror:
                                print('\033[91m  Error: pop server not found.\033[0m')
                                continue
                            user = data[prof]["save_as"]
                        else:
                            print("  \033[91mUsage: > login as <Profile_Name>\033[0m")
                            continue
                    else:
                        print("  \033[95mIncorrect argument - type help\033[0m")
                        continue
                else:
                    info = getinfo()
                    user_prof = info
                    try:
                        server = poplib.POP3(user_prof['server'])
                        server.user(user_prof['email'])
                        server.pass_(user_prof['password'])
                    except poplib.error_proto:
                        try:
                            server = poplib.POP3_SSL(user_prof['server'])
                            server.user(user_prof['email'])
                            server.pass_(user_prof['password'])
                        except poplib.error_proto:
                            print('\033[91m  Error while logging in.\033[0m')
                            continue
                    except socket.gaierror:
                        print('\033[91m  Error: pop server not found.\033[0m')
                        continue
                    try:
                        if not info["save_as"] == "":
                            data[info["save_as"]] = user_prof
                            user = info["email"]
                        else:
                            user = info["save_as"]
                    except KeyError:
                        print('\033[91m  No profile found.\033[0m')
                        continue
            elif args[0] == 'logout':
                user = ''
                user_prof = {}
                server = None
            elif args[0] == 'recv':
                c = list()
                if user == '':
                    print('  \033[91mLogin first!\033[0m')
                    continue
                if len(args) >= 2:
                    try:
                        index = int(args[1])
                    except TypeError:
                        print('  \033[91mUsage: > recv [<index>]\033[0m')
                        continue
                else:
                    index = server.stat()[0]
                msg, sender = get_content(server, index)
                with open('_t_temp.html', 'w') as f:
                    f.write(msg)
                print('\033[95m  Sender:', sender, '\033[0m')
                pattern = re.compile(r'<[^>]+>',re.S)
                msg = pattern.sub('', msg)
                s = re.findall(r"code:(?:\r\n|\n| |<br />)*\d{4}\d{2}?(?:\n|\r\n| )", str(msg))
                s += re.findall(r'码为：(?:\r\n|\n| |<br />)*\d{4}\d{2}?(?:\n|\r\n| )', str(msg))
                s += re.findall(r'=E4=B8=BA=EF=BC=9A(?:\r\n|\n| |<br />)*\d{4}\d{2}?(?:\n|\r\n| )', str(msg))
                for x in s:
                    if x == '':
                        print('\033[91m  No codes detected.')
                        break
                    c.append(re.findall(r'\d{4}\d{2}?', x)[0])
                    print('\033[93m  Detected Code:', c[-1])
                if len(s) == 0:
                    print('\033[91m  No codes detected.\033[0m')
                print("\033[92m  Hint: Enter open to view content.\033[0m")
                print('\033[92m  Hint: Enter copy <number> to copy.\033[0m')
            elif args[0] == 'open':
                if os.path.exists('_t_temp.html'):
                    if os.path.isfile('_t_temp.html'):
                        os.startfile('_t_temp.html')
                    else:
                        print(' \033[91m temp.html is not file. Abort.\033[0m')
                else:
                    print('Not received.')
            elif args[0] == 'info':
                if user == '':
                    print('  \033[91mLogin first!\033[0m')
                    continue
                print('\033[95m  Numbers of email:', server.stat()[0], '\033[0m')
            elif args[0] == 'copy':
                if len(c) == 0:
                    print('\033[91m  Receive one first!\033[0m')
                    continue
                if len(args) >= 2:
                    try:
                        i = int(args[1])
                    except TypeError:
                        print('\033[91m  Argument incorrect.\033[0m')
                        continue
                else:
                    i = -1
                try:
                    copy(c[i])
                except TypeError:
                    print('\03391m  Not a correct index.\033[0m')
                    continue
                print('\033[93m  Success\033[0m')
            data.close()
        except KeyboardInterrupt:
            print('^C')
    data.close()
