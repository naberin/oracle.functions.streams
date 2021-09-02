import io
import json
import logging


def handler(ctx, data: io.BytesIO = None):
    body = {}
    try:
        body = json.loads(data.getvalue())

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
    return body
