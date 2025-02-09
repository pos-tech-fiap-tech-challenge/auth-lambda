import os
import jwt
import botocore.session
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig 
import requests
import json

client = botocore.session.get_session().create_client('secretsmanager')
cache_config = SecretCacheConfig()
cache = SecretCache( config = cache_config, client = client)

secret = json.loads(cache.get_secret_string('secret_jwt_string'))["secret"]
base_path = os.environ["BASE_PATH"]
url_get_users = f"http://{base_path}/lanchonete/customer?cpf="
cpf = None

def lambda_handler(event, context):
    
    print(event)
    try:
        jwt_auth = event["headers"]["Authorization"]
        jwt_decoded = jwt.decode(jwt_auth, secret, algorithms=["HS256", ])
        cpf = jwt_decoded["cpf"]
        print("Autenticando usuário com cpf: "+ cpf)
        path = url_get_users + cpf
        response = requests.get(path)
        print(f"Response da api {path}: {response.text}, status: {response.status_code}")
        if response.status_code == 200:
            print("Usuário logado!")
            return generate_response(event, cpf)
        else:
            print("Usuário não encontrado, será direcionado para o fluxo não logado.")
            return generate_response(event, "0")
    except jwt.exceptions.InvalidTokenError:
        raise Exception("Unauthorized") 
    except Exception as ex:
        print("[WARN] Erro ao tentar autenticar:" + str(ex))
        print("Algum erro inesperado aconteceu durante o processo de autenticação, progredindo para o fluxo não logado")
        return generate_response(event, "0")

def generate_response(event, cpf_data):
    return {
      "principalId": cpf_data,
      "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "execute-api:Invoke",
            "Effect": "Allow",
            "Resource": event["methodArn"]
          }
        ]
      }
    }

