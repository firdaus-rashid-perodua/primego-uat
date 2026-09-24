require('dotenv').config();

const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const helmet = require('helmet'); // 1. Import helmet
const app = express();

console.log('NODE_ENV:', process.env.NODE_ENV);
const isProd = process.env.NODE_ENV === 'production';

// to allow swagger before helmet
let swaggerSpec;
if (!isProd) {
    swaggerSpec = swaggerJsdoc({
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
}


// 2. Global Security Headers Middleware
app.use(
    helmet({
        // Fixes the "Missing X-Frame-Options" finding across all API endpoints
        frameguard: {
            action: 'deny'
        },
        // Custom CSP to satisfy security requirements while allowing Swagger UI to work
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                "script-src": ["'self'", "'unsafe-inline'"],
                "style-src": ["'self'", "'unsafe-inline'"],
                // "img-src": ["'self'", "data:", "https://jsdelivr.net"],
                "img-src": ["'self'", "data:"],
                "frame-ancestors": ["'none'"], // replaces X-Frame-Options, keep frameguard too for older browsers
            }
        }
    })
);

const fooRoutes = require('./routes/foo'); // <-- mounts routes/foo.js



const PORT = Number(process.env.PORT) || 80;

app.get('/health', (req, res) => {
    res.json({ ok: true });
});
// app.use('/api/auth', authRoutes);  --for public access
app.use(express.json());
app.use('/', fooRoutes);

// const swaggerSpec = swaggerJsdoc({
//     definition: {
//         openapi: '3.0.0',
//         info: {
//             title: 'PRIMEGO API',
//             version: '1.0.0'
//         }
//     },
//     apis: ['./routes/*.js']
// });

// app.use(
//     '/api-docs',
//     swaggerUi.serve,
//     swaggerUi.setup(swaggerSpec)
// );

// app.get('/swagger.json', (req, res) => {
//     res.json(swaggerSpec);
// });

app.listen(PORT, () => {
    console.log(`API Server is active on http://localhost:${PORT}`);
});