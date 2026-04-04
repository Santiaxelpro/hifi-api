import requests
import base64

# 🔹 Credenciales
client_id = "txNoH4kkV41MfH25"
client_secret = "dQjy0MinCEvxi1O4UmxvxWnDjt4cgHBPw8ll6nYBk98="

# 🔹 Paso 1: obtener access_token
def get_access_token():
    url = "https://auth.tidal.com/v1/oauth2/token"

    # Basic Auth (igual que tu curl)
    basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()

    headers = {
        "Authorization": f"Basic {basic_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "client_credentials"
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()

    token = response.json()["access_token"]
    return token


# 🔹 Paso 2: buscar tracks
def search_tracks(token):
    url = "https://api.tidal.com/v1/search/tracks"

    headers = {
        "Authorization": f"Bearer {token}"
    }

    params = {
        "query": "Montagem Ladrao",
        "limit": 25,
        "offset": 0,
        "countryCode": "US"
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()

    return response.json()


# 🔹 Ejecutar
if __name__ == "__main__":
    token = get_access_token()
    print("TOKEN:", token[:50], "...")  # solo preview

    results = search_tracks(token)

    # Mostrar resultados básicos
    for track in results.get("items", []):
        print(f"{track['title']} - {track['artist']['name']}")