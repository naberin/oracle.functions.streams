import io
import json
import logging
import requests
import base64
from requests.auth import HTTPBasicAuth
from fdk import response


def base64_decode(encoded):
    # decode base65 encoded stream value
    if encoded:
        base64_bytes = encoded.encode('utf-8')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes.decode('utf-8')
    else:
        return encoded



def buildAuth(username, password):
    return HTTPBasicAuth(username=username, password=password)


def post_stream_log(endpoint, data, auth):
    url = f"{endpoint}/api/log"
    logging.getLogger().info(f"Making POST request to {url}")

    resp = requests.post(url, data=data, auth=auth)
    return resp.status_code


def handler(ctx, data: io.BytesIO = None):
    logger = logging.getLogger()
    logger.info("Starting function.")

    body = {}
    try:
        cfg = dict(ctx.Config())
        logger.info("retrieving config from context")
        logger.info(cfg)

        CFG_USER = cfg["CTX_USER"]
        CFG_PWD = cfg["CTX_PWD"]
        CFG_ENDPOINT = cfg["CTX_ENDPOINT"]

        body = json.loads(data.getvalue())
        logger.info("completed processing data")
        logger.info(body)

        request_data = {
            "action": body["action"],
            "resource": body["resource"],
            "date": body["date"],
            "source": body["source"],
            "level": body["level"],
            "event_id": 1,
            "details": body
        }
        logger.info("completed processing bdy")
        logger.info(request_data)

        auth = buildAuth(username=CFG_USER, password=CFG_PWD)
        post_stream_log(endpoint=CFG_ENDPOINT, data=request_data, auth=auth)

    except (Exception, ValueError) as ex:
        logger.getLogger().info('error parsing json payload: ' + str(ex))
    return body
