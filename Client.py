import sqlite3
import random
import string
import threading
import os
import ctypes
import json
import webbrowser
import requests
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import vk_api
from vk_api.longpoll import VkLongPoll, VkEventType


def main():
    root = tk.Tk()

    def btn_ch():
        """Window chat"""
        root.withdraw()
        window_chat = tk.Toplevel(root)


        def destroy_and_deiconify():
            """Window closing"""
            y_n = tk.messagebox.askyesno(message="All messages will be deleted after closing. Do you want to continue?")
            if y_n is True:
                root.deiconify()
                window_chat.destroy()


        def btnfunc(event):
            """Sending a message"""
            textt.config(state='normal')
            text_value = str(entry.get())

            if text_value == '':
                textt.insert('end', f'{text_value}')
                entry.delete(0, 'end')
                textt.config(state='disabled')
            else:
                t_value = '[' + str(owner_name) + '] ' + text_value

                # Filename creation
                data = text_value.encode("utf-8", "ignore")
                rand_calll = str(''.join(random.choice(string.ascii_letters) for i in range(8)) + '.bin')
                o_id_key = str(owner_id + '.pem')

                # Message encryption
                file_out = open(rand_calll, "wb")
                recipient_key = RSA.import_key(open(o_id_key).read())
                session_key = get_random_bytes(16)
                cipher_rsa = PKCS1_OAEP.new(recipient_key)
                enc_session_key = cipher_rsa.encrypt(session_key)
                cipher_aes = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)
                [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
                file_out.close()

                # Sending a message
                url_mess = vk_session.docs.getMessagesUploadServer(peer_id=user_id)
                url_upl = requests.post(url_mess['upload_url'], files={'file' : open(rand_calll, "rb")})
                result = json.loads(url_upl.text)
                doc_save = vk_session.docs.save(file=result["file"])
                doc_id = doc_save["doc"]

                att_file = 'doc' + str(owner_id) + '_' + str(doc_id["id"])
                vk_session.messages.send(user_id=user_id, attachment=att_file, random_id=0)


                textt.insert('end', f'{t_value}\n')
                entry.delete(0, 'end')
                textt.config(state = 'disabled')


        def user_message(u_message):
            """Displaying a message"""
            textt.config(state='normal')
            us_message = '[' + str(user_name) + '] ' + u_message
            textt.insert('end', f'{us_message}\n')
            textt.config(state='disabled')


        window_chat.title("Messenger")
        window_chat.protocol("WM_DELETE_WINDOW", lambda: destroy_and_deiconify())
        # window size
        width = 800
        height = 500
        screenwidth = window_chat.winfo_screenwidth()
        screenheight = window_chat.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        window_chat.geometry(alignstr)
        window_chat.resizable(width=False, height=False)
        ft = tkfont.Font(family='Helvetica', size=12)

        Button = tk.Button(window_chat, bg='#393d49', justify='center')
        Button["text"] = ""
        Button.place(x=730, y=450, width=70, height=50)
        Button.bind('<Button-1>', btnfunc)

        entry = tk.Entry(window_chat, bg='#999999')
        entry["font"] = ft
        entry.place(x=0, y=450, width=730, height=50)
        entry.bind('<Return>', btnfunc)

        global textt
        textt = tk.Text(window_chat, bg='#ffffff', fg='Black', relief='solid', wrap='word')
        textt["font"] = ft
        textt.place(x=0, y=0, width=800, height=450)
        textt.config(state='disabled')

        db = sqlite3.connect('data.db', timeout=30)
        sql = db.cursor()

        for value in sql.execute("SELECT * FROM data"):
            global main_token
            main_token = value[0]
            global owner_id
            owner_id = value[1]
            global user_id
            user_id = value[2]
            global user_name
            user_name = value[3]

        # Authorization
        session = vk_api.VkApi(token=main_token)
        vk_session = session.get_api()
        u_get = vk_session.users.get()
        u_list = u_get[0]
        global owner_name
        owner_name = u_list["first_name"]


        def listener():
            """Accepts new user's message"""
            for event in VkLongPoll(session).listen():
                if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                    try:
                        u_id = event.user_id
                        message_id = event.message_id
                        if str(u_id) == str(user_id):
                            try:
                                message_info = vk_session.messages.getById(message_ids=message_id)
                                url_att = message_info['items'][0]['attachments'][0]['doc']['url']

                                # Filename creation
                                rand_call = str(''.join(random.choice(string.ascii_letters) for i in range(8)) + '.bin')

                                # Download file
                                u_doc = requests.get(url_att)
                                open(rand_call, "wb").write(u_doc.content)

                                # Message decryption
                                file_in = open(rand_call, "rb")
                                private_key = RSA.import_key(open("private.pem").read())
                                enc_session_key, nonce, tag, ciphertext = \
                                    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
                                cipher_rsa = PKCS1_OAEP.new(private_key)
                                session_key = cipher_rsa.decrypt(enc_session_key)
                                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                                user_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                                file_in.close()

                                # Displaying a message
                                u_message = user_data.decode("utf-8")
                                user_message(u_message)

                                vk_session.messages.markAsRead(peer_id=user_id)
                            except:
                                print('file is missing.')
                                vk_session.messages.markAsRead(peer_id=user_id)
                        else:
                            print(f'User {u_id} wrote a message.')
                    except:
                        print('u_id or message_id.')


        th = threading.Thread(target=listener)
        th.start()


    def create_db():
        """Database creation and key exchange"""
        info_label["text"] = 'Waiting !'
        # Database creation
        db = sqlite3.connect('data.db')
        sql = db.cursor()

        sql.execute("""CREATE TABLE IF NOT EXISTS data (
            maintoken TEXT,
            ownerid TEXT,
            userid TEXT,
            username TEXT
        )""")
        db.commit()

        # Authorization
        session = vk_api.VkApi(token=main_token)
        vk_session = session.get_api()

        # Get owner_id
        u_get = vk_session.users.get()
        u_list = u_get[0]
        owner_id = u_list["id"]

        # Get username
        u_get = vk_session.users.get(user_ids=user_id)
        u_list = u_get[0]
        user_name = u_list["first_name"]

        # Keys generation
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open("receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        # Rename owner's public key 
        os.rename("receiver.pem", str(user_id) + ".pem")


        def send_key():
            """Send key"""
            doc = open(str(user_id) + '.pem', 'r')
            url_mess = vk_session.docs.getMessagesUploadServer(peer_id=user_id)
            url_upl = requests.post(url_mess['upload_url'], files={'file' : doc}).json()
            doc_save = vk_session.docs.save(file=url_upl["file"])
            doc_id = doc_save["doc"]

            att_file = 'doc' + str(owner_id) + '_' + str(doc_id["id"])
            vk_session.messages.send(user_id=user_id, attachment=att_file, random_id=0)


        send_key()

        b = 0
        for event in VkLongPoll(session, preload_messages=True, mode=2).listen():
            if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                try:
                    u_id = event.user_id
                    att = event.attachments
                    if str(u_id) == str(user_id):
                        try:
                            id_att = att['attach1']
                            gHA = vk_session.messages.getHistoryAttachments(peer_id=user_id, media_type='doc')
                            ac_key = gHA['items'][0]['attachment']['doc']['access_key']
                            id_ac_key = str(id_att) + '_' + str(ac_key)
                            doc_info = vk_session.docs.getById(docs=id_ac_key)
                            url_att = doc_info[0]['url']
                            title_att = doc_info[0]['title']

                            filename = str(owner_id) + '.pem'

                            if str(title_att) == str(filename):
                                # Download user's public key
                                u_doc = requests.get(url_att, allow_redirects=True)
                                open(filename, "wb").write(u_doc.content)
                                print('Done')
                                send_key()
                                b += 1
                            else:
                                print('names are different.')
                        except:
                            print('file is missing.')
                    else:
                        print(f'User {u_id} wrote a message.')
                except:
                    print('u_id or att.')

            if b == 1:
                break 
        
        # Filling in the table
        sql.execute(f"INSERT INTO data VALUES (?, ?, ?, ?)", (main_token, owner_id, user_id, user_name))
        db.commit()
        info_label["text"] = 'Done ✓'

        btn_ch()


    def btn_con():
        """Getting token and user_id"""
        global main_token
        main_token = token_entry.get()
        global user_id
        user_id = user_id_entry.get()
        if not user_id or not main_token:
            tk.messagebox.showinfo(message='Insert TOKEN and USER_ID.')
        else:
            create_db()


    def btn_cl():
        """Deleting .db .pem .bin files"""
        y_n = tk.messagebox.askyesno(message="Files .db .bin .pem will be deleted. Do you want to continue?")
        if y_n is True:
            dir_name = os.getcwd()
            files = os.listdir(dir_name)
            for filename in files:
                if filename.endswith('.bin'):
                    os.remove(os.path.join(dir_name, filename))
                elif filename.endswith('.pem'):
                    os.remove(os.path.join(dir_name, filename))
                elif filename.endswith('.db'):
                    os.remove(os.path.join(dir_name, filename))


    def btn_inf():
        """Instruction"""
        def window_chat_destroy():
            btn_info.config(state='normal')
            window_chat.destroy()


        def btn_github():
            webbrowser.open(url="https://github.com/Dan1elSt", new=2)  


        btn_info.config(state='disabled')

        window_chat = tk.Toplevel(root)
        window_chat.title("Rules")
        window_chat.protocol("WM_DELETE_WINDOW", lambda: window_chat_destroy())
        window_chat.grab_set()
        # setting window size
        width = 300
        height = 140
        screenwidth = window_chat.winfo_screenwidth()
        screenheight = window_chat.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        window_chat.geometry(alignstr)
        window_chat.resizable(width=False, height=False)
        ft = tkfont.Font(family='Helvetica', size=12)

        label_instruction=tk.Label(window_chat, fg='#333333', text='Instruction', justify='center')
        label_instruction["font"] = ft
        label_instruction.place(x=20, y=30, width=260, height=20)

        git_button=tk.Button(window_chat, fg='#000000', bg='#efefef', justify='center', text='Github', cursor="hand2")
        git_button["font"] = ft
        git_button.place(x=110, y=70, width=80, height=35)
        git_button["command"] = btn_github
        
        window_chat.mainloop()


    def get_token(event):
        """Redirects to website to get a token"""  
        y_n = tk.messagebox.askyesno(message="Redirect to vkhost.github.io?")
        if y_n is True:
            webbrowser.open(url="https://vkhost.github.io", new=2)     


    root.title('Client')
    # window size
    width = 600
    height = 300
    screenwidth = root.winfo_screenwidth()
    screenheight = root.winfo_screenheight()
    alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
    root.geometry(alignstr)
    root.resizable(width=False, height=False)
    ft = tk.font.Font(family='Helvetica', size=12)

    user_id_label = tk.Label(root, fg='#333333', justify='center', text='USER ID')
    user_id_label["font"] = ft
    user_id_label.place(x=80, y=50, width=240, height=20)

    token_label = tk.Label(root, fg='#333333', justify='center', text='TOKEN')
    token_label["font"] = ft
    token_label.place(x=80, y=100, width=240, height=20)

    info_label = tk.Label(root, fg='#333333', justify='center', relief='groove', text='Done ✓')
    info_label["font"] = ft
    info_label.place(x=460, y=80, width=100, height=60)

    get_token_label = tk.Label(root, fg='#0006AD', justify='center', text='Get TOKEN', cursor="hand2")
    get_token_label["font"] = ft
    get_token_label.place(x=0, y=275, width=100, height=20)
    get_token_label.bind("<Button-1>", get_token)

    user_id_entry = tk.Entry(root, fg='#333333', justify='left', borderwidth='1px')
    user_id_entry["font"] = ft
    user_id_entry.place(x=80, y=70, width=240, height=30)

    token_entry = tk.Entry(root, fg='#333333', justify='left', borderwidth='1px')
    token_entry["font"] = ft
    token_entry.place(x=80, y=120, width=240, height=30)

    btn_connect = tk.Button(root, fg='#000000', bg='#efefef', justify='center', text='Connect', cursor="hand2")
    btn_connect["font"] = ft
    btn_connect.place(x=350, y=80, width=100, height=60)
    btn_connect["command"] = btn_con

    btn_clean = tk.Button(root, fg='#000000', bg='#efefef', justify='center', text='Clean', cursor="hand2")
    btn_clean["font"] = ft
    btn_clean.place(x=150, y=210, width=100, height=60)
    btn_clean["command"] = btn_cl

    btn_chat = tk.Button(root, fg='#000000', bg='#efefef', justify='center', text='Chat', cursor="hand2")
    btn_chat["font"] = ft
    btn_chat.place(x=350, y=210, width=100, height=60)
    btn_chat["command"] = btn_ch

    btn_info = tk.Button(root, fg='#000000', bg='#efefef', justify='center', text='?', cursor="hand2")
    btn_info["font"] = ft
    btn_info.place(x=0, y=0, width=20, height=20)
    btn_info["command"] = btn_inf

    root.mainloop()


def error():
    """"Admin mode"""
    tk.Tk().withdraw()
    tk.messagebox.showinfo(message='Admin mode is required, please run as administrator and try again...')


if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        main()
    else:
        error()