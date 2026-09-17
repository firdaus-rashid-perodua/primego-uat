require('dotenv').config();
const express = require('express');
const mssql_sql = require('mssql');
const oracle_sql = require('oracledb');

const app = express();
const MSSQL_PORT = process.env.MSSQL_PORT;

// Database configuration matched to your connection string
const mssql_dbConfig = {
    user: process.env.MSSQL_USER,        // DATAMART
    password: process.env.MSSQL_PASSWORD, // Perodua25
    server: process.env.MSSQL_SERVER,     // 10.1.115.125
    database: process.env.MSSQL_DATABASE, // MASTER
    options: {
        encrypt: true,                // Matches Encrypt=True
        trustServerCertificate: true, // Matches TrustServerCertificate=True
        appName: 'NodeJS-JSON-API'     // Identifies this application in SQL logs
    },
    // Note: Node-mssql requires a basic pool block even if you don't utilize pooling features, 
    // but setting max: 1 mimics a singular unpooled transaction environment if desired.
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};


// Initialize an Oracle Database Connection Pool for optimal performance
async function initializeDb() {
    try {
        await oracle_sql.createPool({
            user: process.env.ORACLE_USER,
            password: process.env.ORACLE_PASSWORD,
            connectString: process.env.ORACLE_CONNECTION_STRING,
            // poolMax: 10 // Maximum number of simultaneous database connections
        });
        console.log('Successfully connected to Oracle Database pool.');
    } catch (err) {
        console.error('Database connection pool initiation failed:', err);
        process.exit(1);
    }
}


// Establish Connection Pool
const mssql_poolPromise = new mssql_sql.ConnectionPool(mssql_dbConfig)
    .connect()
    .then(pool => {
        console.log(`Successfully connected to MSSQL Server at ${mssql_dbConfig.server}`);
        return pool;
    })
    .catch(err => {
        console.error('MSSQL Database Connection Failed! Details:', err);
        process.exit(1);
    });

app.use(express.json());

// API route pulling from your MASTER database
app.get('/api/data', async (req, res) => {
    try {
        const pool = await mssql_poolPromise;

        // Replace 'YourTableName' with an actual table in your MASTER database
        const result = await pool.request().query(`SELECT TOP (10) [SALES_CENTER_CODE]
      ,[SALES_CENTER_NAME]
      ,[SALES_CENTER_TYPE]
      ,[BOOKING_DATE]
      ,[REG_NO]
      ,[REG_DATE]
      ,[CUSTOMER_OLD_IC_NO]
      ,[CUSTOMER_NEW_IC_NO]
      ,[CUSTOMER_NAME]
      ,[FMC_ID]
      ,[JPJ_MODEL_DESCRIPTION]
      ,[CUSTOMER_NUMBER]
      ,[EXTRACTION_DATE]
  FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
`);

        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }
});




app.listen(MSSQL_PORT, () => {
    console.log(`API Server is active on http://localhost:${MSSQL_PORT}`);
});