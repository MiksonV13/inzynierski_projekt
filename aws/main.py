import json
from dynamo import register_user, login_user, get_profile_from_token, logout_user


def _response(status: int, body: dict):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body),
    }


def lambda_handler(event, context):

    raw_path = event.get("rawPath", "")
    path = raw_path.split("/")[-1]  # login / register / profile / logout
    method = event.get("requestContext", {}).get("http", {}).get("method", "").upper()

    # Parse JSON body safely
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        body = {}

    # REGISTER
    if path == "register" and method == "POST":
        email = body.get("email")
        password = body.get("password")
        result = register_user(email, password)

        if "error" in result:
            return _response(400, {"message": result["error"]})

        return _response(201, result)

    # LOGIN
    if path == "login" and method == "POST":
        email = body.get("email")
        password = body.get("password")
        result = login_user(email, password)

        if "error" in result:
            return _response(401, {"message": result["error"]})

        return _response(200, result)

    # PROFILE
    if path == "profile" and method == "GET":
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        auth = headers.get("authorization", "")

        if not auth.startswith("Bearer "):
            return _response(401, {"message": "Missing or invalid Authorization header"})

        token = auth.split(" ", 1)[1].strip()
        profile = get_profile_from_token(token)

        if not profile:
            return _response(401, {"message": "Invalid or expired token"})

        return _response(200, profile)

    # LOGOUT
    if path == "logout" and method == "GET":
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        auth = headers.get("authorization", "")

        if not auth.startswith("Bearer "):
            return _response(401, {"message": "Missing token"})

        token = auth.split(" ", 1)[1].strip()
        result = logout_user(token)

        return _response(200, result)

    # DEFAULT
    return _response(404, {"message": "Not Found"})
