
# server
- [x] Logging
- [x] TLS
- [ ] RSA
- [x] Routes
  - [x] Login
  - [x] Register
  - [x] Old
    - [x] Gen (key generation for previous times)
  - [ ] Now
    - [x] Encrypt
    - [ ] Decrypt
  - [ ] Later
    - [ ] Encrypt

# cli
- [ ] Subcommands
  - [x] Login
  - [x] Register
  - [ ] Old
  - [ ] Watch
  - [x] Encrypt
  - [ ] Decrypt

# website
TODO

# main

- [x] gerar chaves pseudo-aleatorias com uma cifra, dependentes do email, password, dia e hora (por exemplo SHA256) -> mostrar na pagina/cli
- [x] gerar chaves para uma determinada hora tambem dependentes do mesmo, para cifrar um ficheiro com essa chave -> gerar codigo HMAC-SHA256 ligado à chave
- [x] cifrar com essas chaves e devolver o ficheiro e o hmac do ficheiro ao utilizador
- [ ] permitir tentar decifrar um criptograma com uma chave que o utilizador da -> o sistema verifica o codigo HMAC ligado ao ficheiro e avisa o utilizador se nao estiver certo

# extra

- [x] escolher entre varios tipos de cifra
- [x] escolher HMAC entre 256 e 512
- [ ] keypairs RSA para verificar se quem quer decifrar foi quem decifrou
- [x] signup por email e password no cli 
- [x] signup por email e password no site
- [x] permitir um user aceder qualquer chave que tenha usado no passado
- [x] logs de atividade
- [x] SSL/TLS ou LetsEncrypt para a ligacao do cli/site com o backend

```bash
make install

# register
curl -s -k \
-w '\n' \
-H 'Content-Type: application/json' \
-d '{"name": "baz", "email" : "foo", "client_secret" : "bar"}' \
-X POST https://localhost:3000/register

# login
curl -s -k \
-w '\n' \
-H 'Content-Type: application/json' \
-d '{"email" : "foo", "client_secret" : "bar"}' \
-X POST \
https://localhost:3000/login

# encrypt with now timestamp
curl -v -s -k \
-w '\n' \
-H 'Content-Type: multipart/form-data' \
-H 'Authorization: Bearer ...' \
-F "data=@/path/to/file" \
-F "filename=file" \
-F "cipher=1" \
-F "hmac=1" \
-X POST https://localhost:3000/api/now/encrypt \
-o file.zip
```

openssl dgst -sha256 -hmac $(echo -n "key" | base64 -d) -binary Cargo.toml.enc | awk '{print $1}' | base64

## Building with Nix

```bash
nix build --impure
```
