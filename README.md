# TODO readme file
- [ ] traduzir pra EN
- [ ] por exemplos da cli e tirar os curls
- [ ] por o enunciado
- [ ] agradecimentos ao prof

# server
- [x] Logging
- [x] TLS
- [ ] RSA
- [x] Routes
  - [x] Login
  - [x] Register
  - [x] Old
    - [x] Gen (key generation for previous times)
  - [x] Now
    - [x] Encrypt
    - [x] Decrypt
  - [x] Later
    - [x] Encrypt

# cli
- [x] Subcommands
  - [x] Login
  - [x] Register
  - [x] Old
  - [x] Watch
  - [x] Encrypt
  - [x] Decrypt

# website
TODO

# main

- [x] gerar chaves pseudo-aleatorias com uma cifra, dependentes do email, password, dia e hora (por exemplo SHA256) -> mostrar na pagina/cli
- [x] gerar chaves para uma determinada hora tambem dependentes do mesmo, para cifrar um ficheiro com essa chave -> gerar codigo HMAC-SHA256 ligado à chave
- [x] cifrar com essas chaves e devolver o ficheiro e o hmac do ficheiro ao utilizador
- [x] permitir tentar decifrar um criptograma com uma chave que o utilizador da -> o sistema verifica o codigo HMAC ligado ao ficheiro e avisa o utilizador se nao estiver certo

# extra

- [x] escolher entre varios tipos de cifra
- [x] escolher HMAC entre 256 e 512
- [ ] keypairs RSA 
- [x] signup por email e password no cli 
- [x] signup por email e password no site
- [x] permitir um user aceder qualquer chave que tenha usado no passado
- [x] logs de atividade
- [x] SSL/TLS ou LetsEncrypt para a ligacao do cli/site com o backend


## Running
```bash
# Server
cargo run --bin server

# Cli
cargo run --bin see-u-l4ter

# Example encrypt
cargo run --bin see-u-l4ter encrypt Cargo.lock -c 2 -m 1 -t 2024-05-13-21:47

# Example decrypt
cargo run --bin see-u-l4ter decrypt Cargo.lock.zip
```

## Building with Nix

```bash
nix build --impure
```
