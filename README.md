# main

- [x] gerar chaves pseudo-aleatorias com uma cifra, dependentes do email, password, dia e hora (por exemplo SHA256) -> mostrar na pagina/cli
- [ ] gerar chaves para uma determinada hora tambem dependentes do mesmo, para cifrar um ficheiro com essa chave -> gerar codigo HMAC-SHA256 ligado à chave
- [ ] cifrar com essas chaves e devolver o ficheiro e o hmac do ficheiro ao utilizador
- [ ] permitir tentar decifrar um criptograma com uma chave que o utilizador da. a essa chave adiciona-se o dia/hora atual -> o sistema verifica o codigo HMAC-SHA256 ligado a chave e avisa o utilizador se nao estiver certo

# extra

- [ ] escolher entre varios tipos de cifra
- [ ] escolher HMAC entre 256 e 512
- [ ] keypairs RSA para verificar se quem quer decifrar foi quem decifrou
- [ ] signup por email e password no cli e no site
- [ ] permitir um user aceder qualquer chave que tenha usado no passado
- [ ] logs de atividade
- [x] SSL/TLS ou LetsEncrypt para a ligacao do cli/site com o backend
- [ ] base de dados da backend encriptada

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
-o file.enc
```

## Building with Nix

```bash
nix build --impure
```
