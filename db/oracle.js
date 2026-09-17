// db/oracle.js
// const oracledb = require('oracledb');

// let pool;

// async function getOraclePool() {
//     if (pool) return pool;

//     pool = await oracledb.createPool({
//         user: process.env.ORACLE_USER,
//         password: process.env.ORACLE_PASSWORD,
//         connectString: process.env.ORACLE_CONNECTION_STRING,
//         poolMin: 1,
//         poolMax: 10
//     });

//     return pool;
// }

// module.exports = { getOraclePool };


const oracledb = require('oracledb');
const crypto = require('crypto');

let poolPromise; // declared at the top level to cache the pool singleton

// Your GCM decryption handler
function decryptPassword() {
    try {
        const algorithm = 'aes-256-gcm';
        const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

        const encrypted = process.env.ORACLE_PASSWORD_ENCRYPTED;
        const iv = Buffer.from(process.env.ORACLE_PASSWORD_IV, 'hex');
        const authTag = Buffer.from(process.env.ORACLE_PASSWORD_AUTHTAG, 'hex');

        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAuthTag(authTag); // Required for GCM

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        throw new Error('Failed to decrypt Oracle password: ' + err.message);
    }
}


function getOraclePool() {
    if (!poolPromise) {
        poolPromise = oracledb.createPool({
            user: process.env.ORACLE_USER,
            password: decryptPassword(), // <-- Decrypted safely in memory here
            connectString: process.env.ORACLE_CONNECTION_STRING,
            poolMin: 2,
            poolMax: 10,
            poolIncrement: 1
        })
            .then(pool => {
                console.log('Connected to Oracle database pool successfully.');
                return pool;
            })
            .catch(err => {
                poolPromise = null; // Reset if the creation fails so it can retry later
                console.error('Oracle Connection Pool Error: ', err);
                throw err;
            });
    }
    return poolPromise;
}

module.exports = { getOraclePool };