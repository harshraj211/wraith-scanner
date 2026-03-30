from flask import redirect, render_template_string, request, send_file
import hashlib
import pickle
import requests


def reflected_template():
    return render_template_string("<h1>%s</h1>", request.args.name)


def open_redirect():
    return redirect(request.args.next)


def outbound_fetch():
    return requests.get(request.args.url)


def file_download():
    return send_file(request.args.path)


def sql_lookup(cursor):
    return cursor.execute("SELECT * FROM users WHERE id = " + request.args.user_id)


def unsafe_deserialize(raw_blob):
    return pickle.loads(raw_blob)


def weak_password_hash():
    PASSWORD = request.form.password
    return hashlib.sha1(PASSWORD)
