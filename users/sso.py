import requests

def exchange_google_code(code, redirect_uri, client_id, client_secret):
    token_res = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )
    token_res.raise_for_status()
    access_token = token_res.json()["access_token"]

    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    userinfo.raise_for_status()

    return userinfo.json()


def exchange_github_code(code, redirect_uri, client_id, client_secret):
    token_res = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        },
    )
    token_res.raise_for_status()
    access_token = token_res.json()["access_token"]

    userinfo = requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    userinfo.raise_for_status()

    email_res = requests.get(
        "https://api.github.com/user/emails",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    email_res.raise_for_status()

    email = next(
        e["email"] for e in email_res.json() if e["primary"]
    )

    return {
        "id": userinfo.json()["id"],
        "email": email,
        "name": userinfo.json().get("name") or email.split("@")[0],
    }