// // db/mssql.js
// const sql = require('mssql');

// let pool;

// async function getMssqlPool() {
//     if (pool) return pool;

//     pool = await sql.connect({
//         server: process.env.MSSQL_SERVER,
//         database: process.env.MSSQL_DB,
//         user: process.env.MSSQL_USER,
//         password: process.env.MSSQL_PASSWORD,
//         options: { encrypt: false } // adjust for your environment
//     });

//     return pool;
// }

// module.exports = { getMssqlPool };


const sql = require('mssql');
const crypto = require('crypto');

let poolPromise; // <-- THIS MUST BE DECLARED HERE AT THE TOP LEVEL

function decryptPassword() {
    try {
        const algorithm = 'aes-256-gcm';
        const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

        const encrypted = process.env.MSSQL_PASSWORD_ENCRYPTED;
        const iv = Buffer.from(process.env.MSSQL_PASSWORD_IV, 'hex');
        const authTag = Buffer.from(process.env.MSSQL_PASSWORD_AUTHTAG, 'hex');

        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAuthTag(authTag); // Required for your GCM strategy

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        throw new Error('Failed to decrypt MSSQL password: ' + err.message);
    }
}

function getMssqlPool() {
    if (!poolPromise) {
        const config = {
            user: process.env.MSSQL_USER,
            password: decryptPassword(), // <-- Decrypts cleanly here
            server: process.env.MSSQL_SERVER,
            database: process.env.MSSQL_DATABASE,
            options: {
                encrypt: true,
                trustServerCertificate: true
            }
        };

        poolPromise = new sql.ConnectionPool(config)
            .connect()
            .then(pool => {
                console.log('Connected to MSSQL database.');
                return pool;
            })
            .catch(err => {
                poolPromise = null;
                console.error('MSSQL Connection Pool Error: ', err);
                throw err;
            });
    }
    return poolPromise;
}

module.exports = { getMssqlPool };