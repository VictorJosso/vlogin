import hashlib
import secrets

from appwrite.services.database import Database
from appwrite.services.storage import Storage


def new_service(database: Database, storage: Storage, service_name, service_urls, service_persmissions, service_logo,
                service_access_list):
    l = storage.create_file("629b6a558cd5f4e0e0ca", "unique()", service_logo)
    logo_id = l["$id"]
    service_apikey = secrets.token_urlsafe(128)
    service_apikey_chiffre = hashlib.sha512(service_apikey.encode()).hexdigest()
    database.create_document("services", "unique()",
                             {"name": service_name, "urls": service_urls, "permissions": service_persmissions,
                              "logoID": logo_id, "access_list": service_access_list,
                              "apikey": service_apikey_chiffre})
    return {"status": "success",
            "apikey": service_apikey}
