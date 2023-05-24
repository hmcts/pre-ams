const express = require('express');

const app = express();
const port = 3000;

app.get('/v3/api-docs', (req, res) => {
  res.send('Hello, World!');
});

const server = app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

module.exports = server;
