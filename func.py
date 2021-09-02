import io
import json
import logging
import requests
from requests.auth import HTTPBasicAuth


def buildAuth(username, password):
    return HTTPBasicAuth(username=username, password=password)


def post_stream_log(endpoint, data, auth):
    url = f"{endpoint}/api/log"
    resp = requests.post(url, data=data, auth=auth)
    return resp.status_code


def handler(ctx, data: io.BytesIO = None):
    body = {}
    try:
        cfg = ctx.Config()
        CFG_USER = cfg["CTX_USER"]
        CFG_PWD = cfg["CTX_PWD"]
        CFG_ENDPOINT = cfg["CTX_ENDPOINT"]

        body = json.loads(data.getvalue())

        request_data = {
            "action": body["action"],
            "resource": body["resource"],
            "date": body["date"],
            "source": body["source"],
            "level": body["level"],
            "event_id": 1,
            "details": body
        }

        auth = buildAuth(username=CFG_USER, password=CFG_PWD)
        post_stream_log(endpoint=CFG_ENDPOINT, data=request_data, auth=auth)

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
    return body
