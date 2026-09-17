require('dotenv').config();

const express = require('express');

const fooRoutes = require('./routes/foo'); // <-- mounts routes/foo.js

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT) || 80;

app.get('/health', (req, res) => {
    res.json({ ok: true });
});

// Mount your routes
app.use('/', fooRoutes);
// => GET /from-mssql
// => GET /from-oracle

app.listen(PORT, () => {
    console.log(`API Server is active on http://localhost:${PORT}`);
});