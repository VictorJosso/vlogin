import base64

from flask import Flask, render_template, redirect, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

import os, sys
import dotenv

from .models import Permission
from .utils import *

from appwrite.client import Client
from appwrite.services.users import Users
from appwrite.services.storage import Storage
from appwrite.services.database import Database
from appwrite.services.account import Account
from appwrite.query import Query


dotenv.load_dotenv()

APPWRITE_ENDPOINT = os.getenv("APPWRITE_ENDPOINT")
APPWRITE_PROJECT = os.getenv("APPWRITE_PROJECT")
APPWRITE_APIKEY = os.getenv("APPWRITE_APIKEY")

appwrite_client = Client()
appwrite_client.set_endpoint(APPWRITE_ENDPOINT)
appwrite_client.set_project(APPWRITE_PROJECT)
appwrite_client.set_key(APPWRITE_APIKEY)

appwrite_users = Users(appwrite_client)
appwrite_storage = Storage(appwrite_client)
appwrite_database = Database(appwrite_client)

app = Flask(__name__)
app.config.from_object("config")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)


@app.route("/oauth/")
def login():
    service = request.args.get("service", None)
    url = request.args.get("url", None)

    if service is None or url is None:
        return render_template("badurl.html")

    try:
        _service = appwrite_database.get_document("services", service)
        logo = appwrite_storage.get_file_view("629b6a558cd5f4e0e0ca", _service["logoID"])
        if url not in _service["urls"]:
            return render_template("badurl.html")
        return render_template("login.html", service_name=_service["name"],
                               service_logo=base64.b64encode(logo).decode())

    except Exception:
        print("ERREUR")
        return render_template("badurl.html")


@app.route("/oauth/grant/")
def grant_access():
    service = request.args.get("service", None)
    url = request.args.get("url", None)
    token = request.args.get("token", None)

    print(service, url, token)

    if service is None or url is None or token is None:
        return render_template("badurl.html")

    client = Client()
    client.set_endpoint(APPWRITE_ENDPOINT)
    client.set_project(APPWRITE_PROJECT)
    client.set_jwt(token)

    account = Account(client)
    try:
        a = account.get()
        memberships = appwrite_users.get_memberships(a["$id"])
        roles = []
        for m in memberships["memberships"]:
            if m["teamName"] == service:
                roles = m["roles"]
        try:
            _service = appwrite_database.get_document("services", service)
            logo = appwrite_storage.get_file_view("629b6a558cd5f4e0e0ca", _service["logoID"])
            if len(list(set(_service["access_list"]) & set(roles))) == 0 and len(_service["access_list"]) > 0:
                return render_template("access_denied.html",
                                       service_name=_service["name"],
                                       service_logo=base64.b64encode(logo).decode(),
                                       user_name=a["name"],
                                       user_roles=roles,
                                       url_retour=url + "?status=denied")
            print(_service)
            if url not in _service["urls"]:
                return render_template("badurl.html")
            permissions = [Permission("Votre nom", "fi fi-rr-id-badge"),
                           Permission("Votre adresse mail", "fi fi-rr-envelope")]
            for perm in _service["permissions"]:
                if perm == 1:
                    permissions.append(Permission("Votre numéro de téléphone", "fi fi-rr-phone-call"))
                elif perm == 2:
                    permissions.append(Permission("Votre adresse postale", "fi fi-rr-home"))
                elif perm == 3:
                    permissions.append(Permission("Votre date de naissance", "fi fi-rr-calendar"))
            return render_template("grant.html",
                                   service_name=_service["name"],
                                   service_logo=base64.b64encode(logo).decode(),
                                   permissions=permissions,
                                   user_name=a["name"],
                                   user_roles=roles)
        except Exception as e:
            print(e)
            return render_template("badurl.html")

    except:
        return render_template("badurl.html", h2message="Session expirée",
                               message="Votre session est expirée, ou vous n'êtes pas connecté.")


@app.route("/oauth/validate/")
def validate_login():
    service = request.args.get("service", None)
    url = request.args.get("url", None)
    token = request.args.get("token", None)
    session_id = request.args.get("session_id", None)

    print(service, url, token)

    if service is None or url is None or token is None:
        return render_template("badurl.html")

    client = Client()
    client.set_endpoint(APPWRITE_ENDPOINT)
    client.set_project(APPWRITE_PROJECT)
    client.set_jwt(token)

    account = Account(client)
    try:
        a = account.get()
        memberships = appwrite_users.get_memberships(a["$id"])
        roles = []
        for m in memberships["memberships"]:
            if m["teamName"] == service:
                roles = m["roles"]
        try:
            _service = appwrite_database.get_document("services", service)
            logo = appwrite_storage.get_file_view("629b6a558cd5f4e0e0ca", _service["logoID"])
            if len(list(set(_service["access_list"]) & set(roles))) == 0 and len(_service["access_list"]) > 0:
                return render_template("access_denied.html",
                                       service_name=_service["name"],
                                       service_logo=base64.b64encode(logo).decode(),
                                       user_name=a["name"],
                                       user_roles=roles,
                                       url_retour=url + "?status=denied")
            if url not in _service["urls"]:
                return render_template("badurl.html")
            auth_code = str(secrets.token_urlsafe(32))
            print(auth_code)
            auth_doc = appwrite_database.create_document("authorizations", "unique()",
                                                         {"service_id": service, "auth_code": auth_code})
            user_doc = appwrite_database.list_documents("users", [Query.equal("user_id", [a["$id"]])])
            print("AUTH DOC : ", auth_doc)
            print(user_doc)
            user_doc = user_doc["documents"][0]
            authorizations = user_doc["authorizations"]
            authorizations.append(auth_doc["$id"])
            appwrite_database.update_document("users", user_doc["$id"], {"authorizations": authorizations})
            return redirect(url + "?status=success&client_id=" + a["$id"] + "&code=" + auth_code)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

            return render_template("badurl.html")
    except:
        return render_template("badurl.html", h2message="Session expirée",
                               message="Votre session est expirée, ou vous n'êtes pas connecté.")


@app.route("/oauth/authorize/")
def authorize():
    service_id = request.args.get("service", None)
    code = request.args.get("code", None)
    client_id = request.args.get("client", None)
    service_secret = request.args.get("service_secret", None)

    if service_id is None or code is None or client_id is None or service_secret is None:
        print(service_id, code, client_id, service_secret)
        return jsonify({"status": "refused"})

    try:
        service_details = appwrite_database.get_document("services", service_id)
        if not service_details["apikey"] == hashlib.sha512(service_secret.encode()).hexdigest():
            print("WRONG APIKEY")
            return jsonify({"status": "refused"})
        user_doc = appwrite_database.list_documents("users", [Query.equal("user_id", [client_id])])["documents"][0]
        auth_doc = appwrite_database.list_documents("authorizations", [
            Query.equal("auth_code", [code]),
            Query.equal("service_id", [service_id])
        ])
        print(auth_doc)
        print(user_doc)
        if auth_doc['total'] == 0:
            print("WRONG AUTH CODE")
            return jsonify({"status": "refused"})
        authoriz = []
        for authorization in auth_doc["documents"]:
            if authorization["$id"] in user_doc["authorizations"]:
                authoriz = authorization
                break
        print(authoriz)
        if not authoriz:
            print("WRONG USER")
            return jsonify({"status": "refused"})
        appwrite_database.delete_document("authorizations", authoriz["$id"])
        new_authorization_list = user_doc["authorizations"]
        new_authorization_list.remove(authoriz["$id"])
        print(new_authorization_list)
        appwrite_database.update_document("users", user_doc["$id"], {"authorizations": new_authorization_list})
        data = {"status": "success", "user": {}}
        u = appwrite_users.get(client_id)
        data["user"]["user_id"] = client_id
        data["user"]["name"] = u["name"]
        data["user"]["email"] = u["email"]
        data["user"]["emailVerification"] = u["emailVerification"]

        if 1 in service_details["permissions"]:
            data["user"]["phone_number"] = user_doc["phone_number"]
        if 2 in service_details["permissions"]:
            data["user"]["address"] = user_doc["address"]
        if 3 in service_details["permissions"]:
            data["user"]["birth_date"] = user_doc["birth_date"]

        memberships = appwrite_users.get_memberships(client_id)
        roles = []
        for m in memberships["memberships"]:
            if m["teamName"] == service_id:
                roles = m["roles"]

        data["user"]["roles"] = roles
        return jsonify(data)


    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)

        return jsonify({"status": "refused"})


@app.route("/badurl")
def badurl():
    return render_template("badurl.html")
