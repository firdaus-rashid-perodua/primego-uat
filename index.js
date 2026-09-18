require('dotenv').config();

const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const app = express();

const fooRoutes = require('./routes/foo'); // <-- mounts routes/foo.js

app.use(express.json());
app.use('/', fooRoutes);

const PORT = Number(process.env.PORT) || 80;

app.get('/health', (req, res) => {
    res.json({ ok: true });
});


const swaggerSpec = swaggerJsdoc({
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'PRIMEGO API',
            version: '1.0.0'
        }
    },
    apis: ['./routes/*.js']
});

app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec)
);

app.get('/swagger.json', (req, res) => {
    res.json(swaggerSpec);
});

app.listen(PORT, () => {
    console.log(`API Server is active on http://localhost:${PORT}`);
});