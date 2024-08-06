// server.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const cors = require('cors');
app.use(cors());
const port = 3000;

app.use(bodyParser.json());

// Usuários em memória para exemplo
const users = [];

const SECRET_KEY = 'secreta123';

//rota de registro

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    
    users.push({ username, password: hashedPassword });
    
    res.status(201).send({ message: 'Usuário registrado com sucesso!' });
  });

  //rota de login

  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: 'Credenciais inválidas!' });
    }
    
    const token = jwt.sign({ id: user.username }, SECRET_KEY, { expiresIn: 86400 }); // Expira em 24 horas
    
    res.send({ auth: true, token });
  });

  //proteção de dados

  function verifyJWT(req, res, next) {
    const token = req.headers['x-access-token'];
    
    if (!token) {
      return res.status(403).send({ auth: false, message: 'Nenhum token fornecido.' });
    }
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(500).send({ auth: false, message: 'Falha ao autenticar o token.' });
      }
      
      req.userId = decoded.id;
      next();
    });
  }
  
  app.get('/me', verifyJWT, (req, res) => {
    res.status(200).send({ message: `Bem-vindo, ${req.userId}!` });
  });

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});

