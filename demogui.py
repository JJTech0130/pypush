import json
import tkinter as tk
from base64 import b64encode, b64decode
from getpass import getpass
from tkinter import Text, Entry, Button, StringVar, OptionMenu

import apns
import ids
import imessage

effects = {"None": "", "Slam": "com.apple.MobileSMS.expressivesend.impact", "Loud": "com.apple.MobileSMS.expressivesend.loud", "Gentle": "com.apple.MobileSMS.expressivesend.gentle", "Invisible Ink": "invisibleink", "Echo": "com.apple.messages.effect.CKEchoEffect", "Spotlight": "com.apple.messages.effect.CKSpotlightEffect", "Balloons": "com.apple.messages.effect.CKHappyBirthdayEffect", "Confetti": "com.apple.messages.effect.CKConfettiEffect", "Heart": "com.apple.messages.effect.CKHeartEffect", "Lasers": "com.apple.messages.effect.CKLasersEffect", "Fireworks": "com.apple.messages.effect.CKFireworksEffect", "Celebration": "com.apple.messages.effect.CKSparklesEffect"}


#SETUP IMESSAGE
# Try and load config.json
try:
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

conn = apns.APNSConnection(
    CONFIG.get("push", {}).get("key"), CONFIG.get("push", {}).get("cert")
)


def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None


conn.connect(token=safe_b64decode(CONFIG.get("push", {}).get("token")))
conn.set_state(1)
conn.filter(["com.apple.madrid"])

user = ids.IDSUser(conn)

if CONFIG.get("auth", {}).get("cert") is not None:
    auth_keypair = ids._helpers.KeyPair(CONFIG["auth"]["key"], CONFIG["auth"]["cert"])
    user_id = CONFIG["auth"]["user_id"]
    handles = CONFIG["auth"]["handles"]
    user.restore_authentication(auth_keypair, user_id, handles)
else:
    username = input("Username: ")
    password = getpass("Password: ")

    user.authenticate(username, password)

user.encryption_identity = ids.identity.IDSIdentity(
    encryption_key=CONFIG.get("encryption", {}).get("rsa_key"),
    signing_key=CONFIG.get("encryption", {}).get("ec_key"),
)

if (
        CONFIG.get("id", {}).get("cert") is not None
        and user.encryption_identity is not None
):
    id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
    user.restore_identity(id_keypair)
else:
    import emulated.nac

    vd = emulated.nac.generate_validation_data()
    vd = b64encode(vd).decode()

    user.register(vd)


# Write config.json
CONFIG["encryption"] = {
    "rsa_key": user.encryption_identity.encryption_key,
    "ec_key": user.encryption_identity.signing_key,
}
CONFIG["id"] = {
    "key": user._id_keypair.key,
    "cert": user._id_keypair.cert,
}
CONFIG["auth"] = {
    "key": user._auth_keypair.key,
    "cert": user._auth_keypair.cert,
    "user_id": user.user_id,
    "handles": user.handles,
}
CONFIG["push"] = {
    "token": b64encode(user.push_connection.token).decode(),
    "key": user.push_connection.private_key,
    "cert": user.push_connection.cert,
}

with open("config.json", "w") as f:
    json.dump(CONFIG, f, indent=4)

im = imessage.iMessageUser(conn, user)

def fixup_handle(handle):
    if handle.startswith('tel:+'):
        return handle
    elif handle.startswith('mailto:'):
        return handle
    elif handle.startswith('tel:'):
        return 'tel:+' + handle[4:]
    elif handle.startswith('+'):
        return 'tel:' + handle
    # If the handle starts with a number
    elif handle[0].isdigit():
        # If the handle is 10 digits, assume it's a US number
        if len(handle) == 10:
            return 'tel:+1' + handle
        # If the handle is 11 digits, assume it's a US number with country code
        elif len(handle) == 11:
            return 'tel:+' + handle
    else:  # Assume it's an email
        return 'mailto:' + handle

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyPushGUI")

        self.log_text = Text(root, wrap="word", state="disabled", height=10, width=40)
        self.log_text.pack(pady=10)
        self.recipient_label = tk.Label(root, text="Recipient")
        self.recipient_label.pack()
        self.phone_number_entry = Entry(root, width=15)
        self.phone_number_entry.pack(pady=5)
        self.message_label = tk.Label(root, text="Message")
        self.message_label.pack()
        self.message_entry = Entry(root, width=30)
        self.message_entry.pack(pady=5)

        self.send_button = Button(root, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)
        self.effect_label = tk.Label(root, text="Effect")
        self.effect_label.pack()
        self.effect_var = StringVar()
        self.effect_var.set("None")  # Set default recipient
        self.effect_dropdown = OptionMenu(root, self.effect_var, "None", "Slam", "Loud", "Gentle", "Invisible Ink", "Echo", "Spotlight", "Balloons", "Confetti", "Heart", "Lasers", "Fireworks", "Celebration")
        self.effect_dropdown.pack(pady=5)

    def send_message(self):
        phone_number = self.phone_number_entry.get()
        effect = self.effect_var.get()
        message = self.message_entry.get()
        if message and phone_number:
            log_message = f"{phone_number} ({effect}): {message}\n"
            self.log_text.config(state="normal")
            self.log_text.insert(tk.END, log_message)
            self.log_text.config(state="disabled")
            self.log_text.yview(tk.END)  # Auto-scroll to the latest message
            self.message_entry.delete(0, tk.END)
            im.send(imessage.iMessage(
                text=message,
                participants=[fixup_handle(phone_number)],
                sender=user.current_handle,
                effect=effects[effect]
            ))

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
