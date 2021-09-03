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


def processStream(with_value):
    logger = logging.getLogger()
    try:
        logger.debug({"status": "Starting process", "data": with_value})
        # converting stream object to expected POST payload
        if with_value:

            result = json.loads(with_value)
            result["event_details"] = with_value

            if "event_id" in with_value:
                result["event_id"] = with_value["event_id"]
            else:
                result["event_id"] = None

            logger.debug({"data": result, "status": "completed processing stream"})
            return result

        return {}

    except ValueError as ve:
        logger.info(f"encountered invalid value with log object.")
        raise ValueError


def buildAuth(username, password):
    return HTTPBasicAuth(username=username, password=password)


def post_stream_log(endpoint, data, auth):
    url = f"{endpoint}/api/log"
    logger = logging.getLogger()
    logger.info(f"Making POST request to {url}")

    resp = requests.post(url, json=data, auth=auth)
    logger.info(f"POST - {resp.status_code}")


def handler(ctx, data: io.BytesIO = None):
    logger = logging.getLogger()
    logger.info("Starting function.")

    body = {}
    try:
        # Get Configuration Values from Oracle Functions Application
        cfg = dict(ctx.Config())
        logger.info("retrieving config from context")
        logger.info(cfg)

        CFG_USER = cfg["CTX_USER"]
        CFG_PWD = cfg["CTX_PWD"]
        CFG_ENDPOINT = cfg["CTX_ENDPOINT"]

        # configure auth with given config variables
        auth = buildAuth(username=CFG_USER, password=CFG_PWD)

        # Process data passed upon invocation
        body = json.loads(data.getvalue())

        # Decode base64 encoded stream data
        for log in body:

            if 'value' in log:
                log['value'] = base64_decode(log['value'])

            if 'key' in log:
                log['key'] = base64_decode(log['key'])

            # Process stream data and make post
            logger.info(body)
            processed_log = processStream(with_value=log['value'])
            post_stream_log(endpoint=CFG_ENDPOINT, data=processed_log, auth=auth)

    except (Exception, ValueError) as ex:
        logger.info('error parsing json payload: ' + str(ex))

    # complete function and return response
    logger.info("Completing function.")

    return response.Response(
        ctx, response_data=json.dumps(
            {"status": "completed", "count_processed": len(body)}),
        headers={"Content-Type": "application/json"}
    )