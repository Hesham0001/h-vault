from flask import Flask, flash, redirect, render_template, request, session
from cryptography.fernet import Fernet
import os


def error(message, code=400):
    """Render message as an apology to user."""
    return render_template("error.html", message=message), code

def load_or_create_key():
    key_file = "key.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as key_out:
            key_out.write(key)
        print("🔑 New key generated and saved to key.key")
    else:
        print("✅ Key already exists")
    
    with open(key_file, "rb") as key_in:
        return key_in.read()
