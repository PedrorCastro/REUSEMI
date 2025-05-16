DROP TABLE IF EXISTS usuarios;
 CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  senha TEXT NOT NULL,
  data_cadastro DATETIME DEFAULT CURRENT_TIMESTAMP
 );

 DROP TABLE IF EXISTS categorias;
 CREATE TABLE categorias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL
 );

 DROP TABLE IF EXISTS itens;
 CREATE TABLE itens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  titulo TEXT NOT NULL,
  descricao TEXT NOT NULL,
  categoria_id INTEGER,
  usuario_id INTEGER,
  imagem_url TEXT,
  data_publicacao DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (categoria_id) REFERENCES categorias(id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
 );

 DROP TABLE IF EXISTS trocas;
 CREATE TABLE trocas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER,
  solicitante_id INTEGER,
  destinatario_id INTEGER,
  status TEXT CHECK( status IN ('pendente', 'aceita', 'recusada', 'concluida') ) NOT NULL,
  data_solicitacao DATETIME DEFAULT CURRENT_TIMESTAMP,
  data_conclusao DATETIME,
  FOREIGN KEY (item_id) REFERENCES itens(id),
  FOREIGN KEY (solicitante_id) REFERENCES usuarios(id),
  FOREIGN KEY (destinatario_id) REFERENCES usuarios(id)
 );

 DROP TABLE IF EXISTS mensagens;
 CREATE TABLE mensagens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  troca_id INTEGER,
  usuario_id INTEGER,
  mensagem TEXT NOT NULL,
  data_envio DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (troca_id) REFERENCES trocas(id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
 );

ALTER TABLE itens ADD COLUMN cidade TEXT;

 -- Inserts de exemplo
 INSERT INTO categorias (nome) VALUES ('Livros');
 INSERT INTO categorias (nome) VALUES ('Eletrônicos');
 INSERT INTO usuarios (nome, email, senha) VALUES ('Teste', 'teste@email.com', 'senha123');
 INSERT INTO itens (titulo, descricao, categoria_id, usuario_id, imagem_url) VALUES ('Dom Quixote', 'Livro em bom estado', 1, 1, 'dom_quixote.jpg');