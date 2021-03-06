# -*- coding: utf-8 -*-

from kivy.app import App
from kivy.resources import resource_add_path
from kivy.core.text import LabelBase, DEFAULT_FONT
from kivy.config import Config
from kivy.uix.popup import Popup
from kivy.uix.floatlayout import FloatLayout
from kivy.properties import StringProperty, DictProperty
from kivy.properties import ObjectProperty
from kivy.adapters.listadapter import ListAdapter
from kivy.uix.listview import ListItemButton
from os import path, sep
import requests
from Crypto.Cipher import AES
import base64
from threading import Thread

# フォント設定
font_dir = "{0}{1}font".format(path.dirname(path.abspath(__file__)), sep)
resource_add_path(font_dir)
LabelBase.register(DEFAULT_FONT, 'ipag.ttf')

base_url = "https://pwmanager.azurewebsites.net/{0}"
# base_url = "http://localhost:4000/{0}"
end_of_password = "%=pw=%"


class LoginDialog(FloatLayout):
    start_login = ObjectProperty(None)
    label_login_status = StringProperty()
    exec_method = ObjectProperty(None)
    method_params = DictProperty()
    input_username = StringProperty()
    input_encrypt = StringProperty()

    def __init__(self, message, username, encrypt, method_params, **kwargs):
        super().__init__(**kwargs)
        self.label_login_status = message
        self.method_params = method_params
        self.input_username = username
        self.input_encrypt = encrypt


class ProgressDialog(FloatLayout):
    pass


class AddPasswordDialog(FloatLayout):
    start_add_password = ObjectProperty(None)
    encrypt = ObjectProperty(None)

    def exec_add_password(self, title, body):
        title = self.encrypt(title)
        body = self.encrypt(body)
        self.start_add_password(title, body)


class DataItem(object):
    def __init__(self, item, is_selected=False):
        self.item = item
        self.is_selected = is_selected


class MainWindow(FloatLayout):
    password_title = StringProperty()
    password_body = StringProperty()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.popup = None
        self.username = ""
        self.passwords = []
        self.selected_password = None
        self.password_title = ""
        self.password_body = ""
        self.encrypt_password = ""
        self.config = None
        self.headers = {"Authorization": ""}

    def show_login_dialog(self, exec_method, method_params={}):
        login_dialog = LoginDialog("ログインしてください", self.username, self.encrypt_password,
                                   start_login=self.start_login, exec_method=exec_method,
                                   method_params=method_params)
        self.popup = Popup(title="ログイン", content=login_dialog, size_hint=(0.8, 0.9))
        self.popup.open()

    def login(self, username, otp_token, exec_method, method_params=None):
        url = base_url.format("api-token-auth")
        response = requests.post(url, json={"username": username, "otp_token": otp_token})
        self.popup.dismiss()
        if response.status_code == 200:
            self.headers["Authorization"] = "Token {0}".format(response.json()["token"])
            exec_method(**method_params)
        else:
            self.show_login_dialog(exec_method, method_params)

    def start_login(self, user_id, otp_token, encrypt, exec_method, method_params=None):
        if method_params is None:
            method_params = {}
        self.username = user_id
        self.config.set("general", "username", user_id)
        if len(encrypt) > 32:
            self.encrypt_password = encrypt[:32]
        else:
            self.encrypt_password = encrypt + "_" * (32 - len(encrypt))
        self.popup.dismiss()
        login_progress_dialog = ProgressDialog()
        self.popup = Popup(title="ログイン中", content=login_progress_dialog, size_hint=(0.3, 0.3))
        self.popup.open()
        thread = Thread(target=self.login, args=(user_id, otp_token, exec_method, method_params, ))
        thread.start()

    def encrypt(self, text):
        crypto = AES.new(self.encrypt_password)
        text = text + end_of_password
        to_encrypt = text + "_" * (16 - len(text) % 16)
        encrypted = crypto.encrypt(to_encrypt)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encryptec_text):
        crypto = AES.new(self.encrypt_password)
        decrypted_text = crypto.decrypt(base64.b64decode(encryptec_text.encode())).decode()
        return decrypted_text.split(end_of_password)[0]

    def set_passwords(self, passwords_raw):
        passwords = []
        for password_raw in passwords_raw:
            password = password_raw
            password.update({
                "title": self.decrypt(password_raw["title"]),
                "body": self.decrypt(password_raw["body"])
            })
            passwords.append(password)
        self.passwords = passwords
        adapter_items = []
        for password in passwords:
            mylist_item = password
            mylist_item.update({"is_selected": False})
            adapter_items.append(mylist_item)
        args_converter = lambda row_index, rec: {'text': rec['title'], 'size_hint_y': None, 'height': 25}
        list_adapter = ListAdapter(data=adapter_items,
                                   args_converter=args_converter,
                                   propagate_selection_to_data=True,
                                   cls=ListItemButton,
                                   selection_mode='single')
        list_adapter.bind(on_selection_change=self.set_password_detail)
        self.ids.listview_mylist_items.adapter = list_adapter

    def start_get_passwords(self):
        progress_dialog = ProgressDialog()
        self.popup = Popup(title="取得中", content=progress_dialog, size_hint=(0.3, 0.3))
        self.popup.open()
        Thread(target=self.get_passwords).start()

    def get_passwords(self):
        url = base_url.format("password")
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            self.set_passwords(response.json())
        self.popup.dismiss()
        if 400 <= response.status_code < 500:
            self.show_login_dialog(self.start_get_passwords)

    def show_password_dialog(self):
        add_password_dialog = AddPasswordDialog(start_add_password=self.start_add_password, encrypt=self.encrypt)
        self.popup = Popup(title="パスワードを追加", content=add_password_dialog, size_hint=(0.8, 0.9))
        self.popup.open()

    def start_add_password(self, title, body):
        self.popup.dismiss()
        progress_dialog = ProgressDialog()
        self.popup = Popup(title="追加しています", content=progress_dialog, size_hint=(0.3, 0.3))
        self.popup.open()
        Thread(target=self.add_password, args=(title, body, )).start()

    def add_password(self, title, body):
        url = base_url.format("password")
        params = {
            "title": title,
            "body": body
        }
        response = requests.post(url, json=params, headers=self.headers)
        self.popup.dismiss()
        if 400 <= response.status_code < 500:
            self.show_login_dialog(self.start_add_password, {"title": title, "body": body})
        else:
            self.start_get_passwords()

    def set_password_detail(self, list_adapter, *_):
        if len(list_adapter.selection) == 0:
            return
        index = list_adapter.selection[0].index
        self.selected_password = self.passwords[index]
        self.password_title = self.selected_password["title"]
        self.password_body = self.selected_password["body"]

    def start_change_password(self, title, body):
        progress_dialog = ProgressDialog()
        self.popup = Popup(title="変更しています", content=progress_dialog, size_hint=(0.3, 0.3))
        self.popup.open()
        Thread(target=self.change_password, args=(title, body, )).start()

    def change_password(self, title, body):
        url = base_url.format("password/{0}".format(self.selected_password["id"]))
        params = {
            "title": self.encrypt(title),
            "body": self.encrypt(body)
        }
        response = requests.put(url, json=params, headers=self.headers)
        self.popup.dismiss()
        if 400 <= response.status_code < 500:
            self.show_login_dialog(self.change_password, {"title": title, "body": body})
        else:
            self.start_get_passwords()

    def start_delete_password(self):
        progress_dialog = ProgressDialog()
        self.popup = Popup(title="削除しています", content=progress_dialog, size_hint=(0.3, 0.3))
        self.popup.open()
        Thread(target=self.delete_password).start()

    # TODO add change deleteのメソッドをまとめる
    def delete_password(self):
        url = base_url.format("password/{0}".format(self.selected_password["id"]))
        response = requests.delete(url, headers=self.headers)
        self.popup.dismiss()
        if 400 <= response.status_code < 500:
            self.show_login_dialog(self.delete_password)
        else:
            self.start_get_passwords()


class PassmanApp(App):
    def on_start(self):
        self.root.config = self.config
        self.root.show_login_dialog(self.root.start_get_passwords)

    def build(self):
        window = MainWindow()
        window.username = self.config.get("general", "username")
        print(self.config.get("general", "username"))
        return window

    def build_config(self, config):
        config.read("passman.ini")

    def build_settings(self, settings):
        settings.add_json_panel('Download Settings', self.config, filename='settings.json')

    def on_config_change(self, config, section, key, value):
        if key == "username":
            self.root.username = value


if __name__ == "__main__":
    Config.set('graphics', 'width', '700')
    Config.set('graphics', 'height', '350')
    PassmanApp().run()
