# main
- gerar chaves pseudo-aleatorias com uma cifra, dependentes do email, password, dia e hora (por exemplo SHA256) -> mostrar na pagina/cli
- gerar chaves para uma determinada hora tambem dependentes do mesmo, para cifrar um ficheiro com essa chave -> gerar codigo HMAC-SHA256 ligado à chave
- permitir tentar decifrar um criptograma com uma chave que o utilizador da. a essa chave adiciona-se o dia/hora atual -> o sistema verifica o codigo HMAC-SHA256 ligado a chave e avisa o utilizador se nao estiver certo

# extra
- escolher entre varios tipos de cifra
- escolher HMAC entre 256 e 512
- para alem do HMAC, ter keypairs RSA para verificar se quem quer decifrar foi quem decifrou
- signup por email e password no cli e no site
- permitir um user aceder qualquer chave que tenha usado no passado
- logs de atividade
- SSL/TLS ou LetsEncrypt para a ligacao do cli/site com o backend
- base de dados da backend encriptada

