/*
http://10.60.22.62/from-oracle
http://10.60.22.62/from-mssql
http://10.60.22.62/get-users
*/

// routes/foo.js
const express = require('express');
const { getMssqlPool } = require('../db/mssql');
const { getOraclePool } = require('../db/oracle');
const oracledb = require('oracledb');
const { parse } = require('dotenv');
const { Client } = require('ldapts');
const jwt = require('jsonwebtoken');
// const crypto = require('crypto');

const router = express.Router();
const authenticate = require('../middleware/authenticate');


const algorithm = 'aes-256-gcm';
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
// const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_super_secret_key';



// ORACLE DATE FORMATTER
const formatter = new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric'
});

const formatOracleDate = (date) =>
    formatter.format(date).replace(/[\s,]+/g, '-').toUpperCase();
// END ORACLE DATE FORMATTER


// Reusable helper function to log login audit records safely
async function logAuditTrail(username, status) {
    let conn;
    try {
        const pool = await getOraclePool();
        conn = await pool.getConnection();

        await conn.execute(
            `INSERT INTO bma_login_audit_trail (
                username, 
                login_date, 
                status
             ) VALUES (
                :username, 
                SYSDATE, 
                :status
             )`,
            { username, status }
        );

        await conn.commit();
        console.log(`[Oracle] Login successfully audited (${status}) for user: ${username}`);
    } catch (dbErr) {
        console.error(`Oracle database auto-insert failed, skipping audit record (${status}):`, dbErr.message || dbErr);
        if (conn) {
            try { await conn.rollback(); } catch (rbErr) { console.error('Oracle rollback failed:', rbErr.message); }
        }
    } finally {
        if (conn) {
            try { await conn.close(); } catch (closeErr) { console.error('Error closing Oracle connection:', closeErr.message); }
        }
    }
}

/**
 * @openapi
 * /from-mssql:
 *   get:
 *     summary: MSSQL connection test
 *     description: Retrieves data from the MS SQL instance.
 *     responses:
 *       200:
 *         description: Successfully retrieved data.
 *       500:
 *         description: Database connection or query error.
 */
router.get('/from-mssql', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT TOP 1 1 as MSSQL
        FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]`);
        //res.json(result.recordset);

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

/**
 * @openapi
 * /from-oracle:
 *   get:
 *     summary: ORACLE connection test
 *     description: Retrieves data from the MS SQL instance.
 *     responses:
 *       200:
 *         description: Successfully retrieved data.
 *       500:
 *         description: Database connection or query error.
 */
router.get('/from-oracle', authenticate, async (req, res) => {
    try {
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();

        const result = await conn.execute(`
            select 1 as oracle from bma_configuration_master where rownum = 1
            `,
            [], // Bind variables (empty array since you don't have any)
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );

        await conn.close();
        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


/**
 * @openapi
 * /login-direct:
 *   post:
 *     summary: Active Directory / LDAP Login protocol
 *     description: Authenticates a user against the corporate LDAP directory after verifying registration status in the Oracle database.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: The user's corporate username or email address.
 *                 example: m2 username
 *               password:
 *                 type: string
 *                 format: password
 *                 description: The user's plaintext Windows/LDAP password.
 *                 example: P@ssword123
 *     responses:
 *       200:
 *         description: Authentication successful.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Login successful
 *       400:
 *         description: Bad Request. Missing parameters.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Username and password are required
 *       401:
 *         description: Unauthorized. Account is not registered or active.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: User account not registered in PRIME GO.
 *       500:
 *         description: Internal Server Error. Database or system failure.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Database error during user verification
 */
router.post('/login-direct', async (req, res) => {
    let { username, password } = req.body;
    let useremail = username;

    // 1. Check if username or password are empty strings
    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: 'Username and password are required'
        });
    }

    // Clean spaces and check for the domain suffix
    username = username.trim();
    const domain = '@perodua.com.my';

    if (!username.toLowerCase().endsWith(domain)) {
        useremail = `${username}${domain}`;
    }

    const pass_decrypt = password;

    //ORACLE user checking
    // --- PRE-LDAP ORACLE USER CHECK ---
    let dbCheckConn;
    try {
        const pool = await getOraclePool();
        dbCheckConn = await pool.getConnection();

        const checkResult = await dbCheckConn.execute(
            `SELECT 1
             FROM bma_users
             WHERE upper(user_email) = upper(:useremail)
             AND record_status = 'E'`,
            { useremail: useremail }
        );

        // If no rows are returned, the user is invalid or not active
        if (!checkResult.rows || checkResult.rows.length === 0) {
            console.warn(`[Oracle] Blocked login attempt: User '${username}' not found or inactive.`);

            // Log FAILED status to audit trail
            await logAuditTrail(username, 'UNREGISTERED');

            return res.status(401).json({
                success: false,
                message: 'User account not registered in PRIME GO.'
            });
        }

        console.log(`[Oracle] User '${username}' verified successfully as PRIMEGO users.`);
    } catch (dbErr) {
        console.error('Oracle database user existence check failed:', dbErr.message || dbErr);
        return res.status(500).json({
            success: false,
            message: 'Database error during user verification'
        });
    } finally {
        if (dbCheckConn) {
            try { await dbCheckConn.close(); } catch (closeErr) { console.error('Error closing Oracle connection:', closeErr.message); }
        }
    }


    //LDAP Start
    const client = new Client({
        url: 'ldap://perodua.com.my',
        imeout: 5000,          // Prevents the request from hanging forever if LDAP is down
        connectTimeout: 5000
    });
    try {
        await client.bind(useremail, pass_decrypt);
        console.log(`[LDAP] Direct LDAP login successful for: ${useremail}`);
        const ldapFilter = `(|(mail=${username})(mail=${username}@perodua.com.my)(sAMAccountName=${username}))`;


        const { searchEntries } = await client.search(
            'DC=perodua,DC=com,DC=my',
            {
                scope: 'sub',
                //filter: '(sAMAccountName=firdaus.rashid)',
                // filter: `(mail=${username})`,
                filter: ldapFilter, // 👈 Change this line to use the variable!
            }
        );

        // Close connection before sending successful response
        await client.unbind();

        // --- SUCCESSFUL LOGIN AUDIT ---
        await logAuditTrail(username, 'SUCCESS');

        // Ensure searchEntries exists and has elements
        const userObj = searchEntries && searchEntries.length > 0 ? searchEntries[0] : null;

        // Handle array vs string formats depending on your ldapts configuration
        let displayName = "User"; // fallback default

        // if (userObj) {
        //     if (Array.isArray(userObj.cn)) {
        //         displayName = userObj.cn[0]; // Take first item if it's an array
        //     } else if (typeof userObj.cn === 'string') {
        //         displayName = userObj.cn;
        //     }
        // }

        if (userObj) {
            // 1. Check 'displayName' first (This holds "Ahmad Firdaus Bin Abd Rashid")
            const nameAttribute = userObj.displayName || userObj.cn;

            if (Array.isArray(nameAttribute)) {
                displayName = nameAttribute[0]; // Take first item if it's an array
            } else if (typeof nameAttribute === 'string') {
                displayName = nameAttribute;
            }
        }

        //JWT Token assign after success LDAP
        const token = jwt.sign(
            { username },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        return res.json({
            success: true,
            message: 'Login successful',
            token,
            // user: userObj
            user: [{
                email: username,
                name: displayName // Your mobile frontend can map directly to 'name'
            }]
        });

    } catch (err) {
        console.error('Invalid credentials or LDAP connection error:', err.message || err);

        // --- FAILED LDAP LOGIN AUDIT ---
        await logAuditTrail(username, 'FAILED');

        // 5. Attempt clean unbind layout inside catch block to avoid unhandled crashes
        try {
            await client.unbind();
        } catch (unbindErr) {
            // Silently suppress if connection was already dead
        }

        return res.status(401).json({
            success: false,
            message: 'Invalid credentials',
            error: err.message || 'Unauthorized'
        });
    } /* finally {
        await client.unbind();
    } */
});


// start BMA (PRIME-GO) query


router.get('/api/user-access', authenticate, async (req, res) => {
    try {

        const { username } = req.query;

        // username = 'firdaus.rashid@perodua.com.my'
        const user_name = username || '';
        const username1 = user_name.split('@')[0];


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select login_id as users, acl_registration, acl_booking, acl_parts, acl_service 
from bma_users
where login_id = upper(:username)
and record_status = 'E'
            `,
            {
                username: username1
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/user-access Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});



/**
 * @openapi
 * /api/dashboard/ack_registration:
 *   get:
 *     summary: ACK submission
 *     description: Retrieves data from the MS SQL instance.
 *     responses:
 *       200:
 *         description: Successfully retrieved data.
 *       500:
 *         description: Database connection or query error.
 */
router.get('/api/dashboard/ack_registration', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';

        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
SELECT 
    NVL(MAX(status), 'ACK') AS status,
    NVL(SUM(TO_NUMBER(doc_total)), 0) AS amount
FROM vsales.SNDSV_JPJ_MONITORING
WHERE doc_type = 'EDAFTAR'
  AND status = 'ACK'
  AND created_date >= TRUNC(SYSDATE)
  AND created_date < TRUNC(SYSDATE) + 1
            `,
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});

router.get('/api/dashboard/ack_registration_temp', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
SELECT 'ACK' as STATUS, to_number(sectionvalue) as AMOUNT
FROM bma_configuration_master
WHERE configtype = 'ACK_EDAFTA'
and sectionname = 'ACK_EDAFTAR'
and recordstatus = 'E'
            `,
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_temp  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/ack_registration_outlet_list', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  a.chassis_no ,a.sales_center_code,b.fmr_id,a.jpj_status
from vsales.sndsv_jpj_transactions a, dna.sndsd_vehicles b
where a.jpj_status = 'ACK'
and a.chassis_no = b.chassis_number
and a.creation_date >= trunc(sysdate)
and a.creation_date < trunc(sysdate) + 1
--and a.sales_center_code = ''
and a.indicator = '0'
            `,
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_temp  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/ack_registration_region', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  'ACK' as status, outl.region, outl.region_2, count(*) as total_ack
from vsales.sndsv_jpj_transactions jpj, dna.sndsd_vehicles veh, bma_outlet_type outl, dna.sndsd_family_model_colors a, dna.sndsd_vehicle_colors b, dna.sndsd_family_models c, dna.sndsd_vehicle_family_groups d, dna.sndsd_vehicle_families e
where jpj.jpj_status = 'ACK'
and jpj.chassis_no = veh.chassis_number
and a.creation_date >= trunc(sysdate)
and a.creation_date < trunc(sysdate) + 1
and jpj.indicator = '0'
and jpj.sales_center_code = outl.sls_code
--and jpj.sales_center_code = :outletcode
AND veh.fmr_id = a.id
AND a.vcl_code = b.vcl_code
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
group by outl.region, outl.region_2
            `,
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_temp  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});

router.get('/api/dashboard/ack_registration_outlet', authenticate, async (req, res) => {
    try {

        const { outletcode } = req.query;

        const outletCode = outletcode || '121178';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  jpj.sales_center_code as outlet_code, REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i') AS MODEL, count(*) as TOTAL_ACK
from vsales.sndsv_jpj_transactions jpj, dna.sndsd_vehicles veh, dna.sndsd_family_model_colors a, dna.sndsd_vehicle_colors b, dna.sndsd_family_models c, dna.sndsd_vehicle_family_groups d, dna.sndsd_vehicle_families e 
where jpj.jpj_status = 'ACK'
and jpj.chassis_no = veh.chassis_number
and a.creation_date >= trunc(sysdate)
and a.creation_date < trunc(sysdate) + 1
and jpj.indicator = '0'
and jpj.sales_center_code = :outletcode
AND veh.fmr_id = a.id
AND a.vcl_code = b.vcl_code
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
GROUP BY jpj.sales_center_code, REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i')
            `,
            {
                outletcode: outletCode
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_outlet  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});



router.get('/api/dashboard/ack_registration_model', authenticate, async (req, res) => {
    try {

        const { outletcode } = req.query;

        const outletCode = outletcode || '121178';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i') AS MODEL, count(*) as TOTAL_ACK
from sndsv_jpj_transactions jpj, sndsd_vehicles veh, sndsd_family_model_colors a, sndsd_vehicle_colors b, sndsd_family_models c, sndsd_vehicle_family_groups d, sndsd_vehicle_families e 
where jpj.jpj_status = 'ACK'
and jpj.chassis_no = veh.chassis_number
and a.creation_date >= trunc(sysdate)
and a.creation_date < trunc(sysdate) + 1
and jpj.indicator = '0'
--and jpj.sales_center_code = :outletcode
AND veh.fmr_id = a.id
AND a.vcl_code = b.vcl_code
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
GROUP BY REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i')
            `,
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_model  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/ack_registration_model_outlet', authenticate, async (req, res) => {
    try {

        const { outletcode } = req.query;

        const outletCode = outletcode || '121178';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  jpj.sales_center_code as outlet_code, REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i') AS MODEL, count(*) as TOTAL_ACK
from sndsv_jpj_transactions jpj, sndsd_vehicles veh, sndsd_family_model_colors a, sndsd_vehicle_colors b, sndsd_family_models c, sndsd_vehicle_family_groups d, sndsd_vehicle_families e 
where jpj.jpj_status = 'ACK'
and jpj.chassis_no = veh.chassis_number
and a.creation_date >= trunc(sysdate)
and a.creation_date < trunc(sysdate) + 1
and jpj.indicator = '0'
and jpj.sales_center_code = :outletcode
AND veh.fmr_id = a.id
AND a.vcl_code = b.vcl_code
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
GROUP BY jpj.sales_center_code, REGEXP_REPLACE(d.description, '^PERODUA \s*|\s* \\(NEW\\)$', '', 1, 0, 'i')
            `,
            {
                outletcode: outletCode,
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_model  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/ack_registration_list_outlet', authenticate, async (req, res) => {
    try {

        const { outletcode } = req.query;

        const outletCode = outletcode || '121178';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  jpj.sales_center_code as outlet_code, count(*) as total_ack
from vsales.sndsv_jpj_transactions jpj, dna.sndsd_vehicles veh, dna.sndsd_family_model_colors a, dna.sndsd_vehicle_colors b, dna.sndsd_family_models c, dna.sndsd_vehicle_family_groups d, dna.sndsd_vehicle_families e 
where jpj.jpj_status = 'ACK'
and jpj.chassis_no = veh.chassis_number
and jpj.creation_date >= trunc(sysdate)
and jpj.creation_date < trunc(sysdate) + 1
and jpj.indicator = '0'
--and jpj.sales_center_code = :outletcode
AND veh.fmr_id = a.id
AND a.vcl_code = b.vcl_code
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
GROUP BY jpj.sales_center_code
            `,
            // {
            //     outletcode: outletCode
            // },
            [],
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration_list_outlet  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


/**
 * @openapi
 * /api/dashboard/year_regActual:
 *   get:
 *     summary: Registration - Yearly Actual
 *     description: Retrieves data from the MS SQL instance.
 *     responses:
 *       200:
 *         description: Successfully retrieved data.
 *       500:
 *         description: Database connection or query error.
 */
router.get('/api/dashboard/year_regActual', authenticate, async (req, res) => {

    const { year } = req.query;
    const parsedYear = year || '2025';

    try {
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('yearParam', parseInt(parsedYear)).query(`SELECT COUNT(*) as 'total_reg_year'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE YEAR(REG_DATE) = @yearParam`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/year_regActual  Params: " + JSON.stringify(req.query));
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/year_regActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});


router.get('/api/dashboard/year_regTarget_2', authenticate, async (req, res) => {

    const { year } = req.query;
    const parsedYear = year || '2025';

    try {
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('yearParam', parseInt(parsedYear)).query(`SELECT SUM(Target) as 'TARGET_REG_YEAR'
    FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
    WHERE  YEAR = @yearParam
    AND Parameter = 'New Car Reg'`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/year_regTarget  Params: " + JSON.stringify(req.query));
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

/**
 * @openapi
 * /api/dashboard/year_regTarget:
 *   get:
 *     summary: Registration - Yearly Target
 *     description: Retrieves data from the MS SQL instance.
 *     responses:
 *       200:
 *         description: Successfully retrieved data.
 *       500:
 *         description: Database connection or query error.
 */
router.get('/api/dashboard/year_regTarget', authenticate, async (req, res) => {
    try {

        const { year } = req.query;
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
SELECT to_number(sectionvalue) as target_reg_year
FROM bma_configuration_master
WHERE configtype = 'YRLY_TARGT'
and sectionname = 'YEAR_REG_TARGET'
and recordstatus = 'E'
and attr1 = :year
            `,
            {
                year: parsedYear
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/ack_registration  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/mnt_regActual', authenticate, async (req, res) => {
    try {

        // 1. Get query parameters from the request URL
        const { month, year } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`SELECT COUNT(*) as 'total_reg_month'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE MONTH(REG_DATE) = @monthParam
      AND YEAR(REG_DATE) = @yearParam`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);


        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_regActual  Params: " + JSON.stringify(req.query));
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/mnt_regActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});


router.get('/api/dashboard/mnt_regTarget', authenticate, async (req, res) => {
    try {
        const { month, year } = req.query;

        // Fallback defaults if parameters are missing from the URL call
        // const queryMonth = month || '05';
        // const queryYear = year || '2025';
        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`SELECT ISNULL(SUM(Target), 0) as 'target_reg_month'
FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
WHERE YEAR = @yearParam
  AND MONTH = @monthParam
  --AND REGION = 'C1'
  AND Parameter = 'New Car Reg'`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2)

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_regTarget Params: " + JSON.stringify(req.query));
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


router.get('/api/dashboard/mnt_bookActual', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT COUNT(*) as 'total_book_month'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE MONTH(REG_DATE) = '05'
      AND YEAR(REG_DATE) = '2025'`);
        //res.json(result.recordset);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_bookActual");
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


router.get('/api/dashboard/mnt_bookTarget', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT SUM(Target) as 'target_book_month'
    FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
    WHERE  YEAR = '2025'
    AND MONTH = '5'
    --AND REGION = 'C1'
    AND Parameter = 'New Car Reg'`);
        //res.json(result.recordset);

        // console.log(`[] success: /api/dashboard/mnt_bookTarget`);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_bookTarget");
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


router.get('/api/dashboard/mnt_serviceActual', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT COUNT(*) as 'total_reg_month'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE MONTH(REG_DATE) = '05'
      AND YEAR(REG_DATE) = '2025'`);
        //res.json(result.recordset);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_serviceActual");
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


router.get('/api/dashboard/mnt_serviceTarget', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT SUM(Target) as 'target_reg_month'
    FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
    WHERE  YEAR = '2025'
    AND MONTH = '5'
    --AND REGION = 'C1'
    AND Parameter = 'New Car Reg'`);
        //res.json(result.recordset);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_serviceTarget");
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


router.get('/api/dashboard/mnt_partActual', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT COUNT(*) as 'total_reg_month'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE MONTH(REG_DATE) = '05'
      AND YEAR(REG_DATE) = '2025'`);
        //res.json(result.recordset);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_partActual");
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


router.get('/api/dashboard/mnt_partTarget', authenticate, async (req, res) => {
    try {
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT SUM(Target) as 'target_reg_month'
    FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
    WHERE  YEAR = '2025'
    AND MONTH = '5'
    --AND REGION = 'C1'
    AND Parameter = 'New Car Reg'`);
        //res.json(result.recordset);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success: /api/dashboard/mnt_partTarget");
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


// List actual monthly registration by month
router.get('/api/registration/mnt_listActual', authenticate, async (req, res) => {
    try {
        const { month, year } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_REG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam 
      AND TR2.Year = @yearParam
    GROUP BY OTL2.Region_2
),
ActualData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        COUNT(*) AS ACTUAL_REG_COUNT
    FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.REG_DATE) = @monthParam
      AND YEAR(AC2.REG_DATE) = @yearParam
    GROUP BY OTL2.Region_2
)
SELECT 
    ISNULL(t.[REGION], a.[REGION]) AS [REGION],
    
    -- New Descriptive Region Column (Added FMD label map)
    CASE ISNULL(t.[REGION], a.[REGION])
        WHEN 'C1'  THEN 'Central 1'
        WHEN 'C2'  THEN 'Central 2'
        WHEN 'EC1' THEN 'East Coast 1'
        WHEN 'EC2' THEN 'East Coast 2'
        WHEN 'EM'  THEN 'East Malaysia'
        WHEN 'N'   THEN 'Northern'
        WHEN 'S'   THEN 'Southern'
        WHEN 'FMD' THEN 'FMD' -- Maps code to descriptive name
        ELSE ISNULL(t.[REGION], a.[REGION]) 
    END AS REGION_NAME,

    ISNULL(t.TARGET_REG_COUNT, 0) AS TARGET_REG_COUNT,
    ISNULL(a.ACTUAL_REG_COUNT, 0) AS ACTUAL_REG_COUNT,
    
    -- 1. No Decimal Places (rounded to nearest integer)
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND((ISNULL(a.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT, 0) AS INT)
    END AS REG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST((ISNULL(a.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,1))
    END AS REG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST((ISNULL(a.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,2))
    END AS REG_PCTG_2

FROM TargetData t
FULL OUTER JOIN ActualData a 
    ON t.[REGION] = a.[REGION]

-- Custom Sorting Rule
ORDER BY 
    CASE WHEN ISNULL(t.[REGION], a.[REGION]) = 'FMD' THEN 1 ELSE 0 END ASC, 
    ISNULL(t.[REGION], a.[REGION]) ASC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_listActual  Params: " + JSON.stringify(req.query));
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


// List actual monthly registration by month (Model)
router.get('/api/registration/mnt_listActualModel', authenticate, async (req, res) => {
    try {
        const { month, year } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`
WITH TargetSummary AS (
    -- Step 1: Sum up targets per model first
    SELECT 
        Model,
        SUM(TRY_CAST(Target AS INT)) AS TARGET_REG_COUNT
    FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
    WHERE Parameter = 'New Car Reg'
      AND Year = @yearParam
      AND Month = @monthParam
      AND Model <> 'AXIA E'
    GROUP BY Model
),
RegistrationSummary AS (
    -- Step 2: Get total actual registrations per model using a clean JOIN condition
    SELECT 
        t.Model,
        COUNT(*) AS ACTUAL_REG_COUNT
    FROM (
        SELECT DISTINCT Model 
        FROM [DM_BRONZE].[CRKPI].[FlatFile_Target] 
        WHERE Parameter = 'New Car Reg' AND Year = 2025 AND Month = 5 AND Model <> 'AXIA E'
    ) t
    INNER JOIN [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg] r
        ON r.JPJ_MODEL_DESCRIPTION LIKE '%' + t.Model + '%'
    WHERE MONTH(r.REG_DATE) = @monthParam
      AND YEAR(r.REG_DATE) = @yearParam
      --AND r.JPJ_MODEL_DESCRIPTION <> 'AXIA - 1000 E (MANUAL)'
    GROUP BY t.Model
)
-- Step 3: Combine everything and calculate all required percentages safely
SELECT 
    t.Model,
    ISNULL(r.ACTUAL_REG_COUNT, 0) AS ACTUAL_REG_COUNT,
    ISNULL(t.TARGET_REG_COUNT, 0) AS TARGET_REG_COUNT,

    -- 1. No Decimal Places (rounded to nearest integer)
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND((ISNULL(r.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT, 0) AS INT)
    END AS REG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST((ISNULL(r.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,1))
    END AS REG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST((ISNULL(r.ACTUAL_REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,2))
    END AS REG_PCTG2

FROM TargetSummary t
LEFT JOIN RegistrationSummary r ON t.Model = r.Model
ORDER BY ACTUAL_REG_COUNT DESC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_listActualModel  Params: " + JSON.stringify(req.query));
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



// List actual monthly registration by month (Outlets)
router.get('/api/registration/mnt_listRegionOutlet', authenticate, async (req, res) => {
    try {
        const { month, year, region } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';

        // console.log(parsedRegion);

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_REG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam 
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, TR2.[Outlet Code]
),
ActualData AS (
    SELECT 
        OTL2.Region_2 AS [REGION], 
        AC2.SALES_CENTER_CODE AS OUTLET_CODE, 
        AC2.SALES_CENTER_NAME AS OUTLET_NAME, 
        COUNT(*) AS REG_COUNT
    FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.REG_DATE) = @monthParam
      AND YEAR(AC2.REG_DATE) = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, AC2.SALES_CENTER_CODE, AC2.SALES_CENTER_NAME
)
SELECT 
    ISNULL(a.[REGION], t.[REGION]) AS [REGION],
    ISNULL(a.OUTLET_CODE, t.OUTLET_CODE) AS OUTLET_CODE,
    ISNULL(a.OUTLET_NAME, 'No Name Registered') AS OUTLET_NAME,
    ISNULL(t.TARGET_REG_COUNT, 0) AS TARGET_REG_COUNT,
    ISNULL(a.REG_COUNT, 0) AS ACTUAL_REG_COUNT,
    
    -- 1. No Decimal Places (rounded to nearest integer)
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT, 0) AS INT)
    END AS REG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,1))
    END AS REG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,2))
    END AS REG_PCTG_2

FROM TargetData t
FULL OUTER JOIN ActualData a 
    ON t.OUTLET_CODE = a.OUTLET_CODE
ORDER BY REG_PCTG_2 DESC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        // To change 'Veh Br - ' to 'PSSB' 
        const updatedRecords = result.recordset.map(item => {
            if (item.OUTLET_NAME && item.OUTLET_NAME.startsWith('Veh Br-')) {
                return {
                    ...item,
                    OUTLET_NAME: item.OUTLET_NAME.replace('Veh Br-', 'PSSB ')
                };
            }
            return item;
        });

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_listRegionOutlet Params: " + JSON.stringify(req.query));




        // Ori
        /* res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        }); */


        // Modified JSON
        res.status(200).json({
            success: true,
            count: updatedRecords.length,
            data: updatedRecords
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});



// List actual monthly registration by month (Outlets)
router.get('/api/registration/mnt_listModelOutlet', authenticate, async (req, res) => {
    try {
        const { month, year, region, outletcode } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';
        const parsedOutletCode = outletcode || '522105';

        // console.log(parsedRegion);

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).input('outletCodeParam', parsedOutletCode).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        TR2.Model AS [MODEL],
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_REG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND TR2.[Outlet Code] = @outletCodeParam
      AND TR2.Model <> 'AXIA E'
    GROUP BY OTL2.Region_2, TR2.[Outlet Code], TR2.Model
),
ActualData AS (
    SELECT 
        t.[REGION],
        t.OUTLET_CODE,
        t.[MODEL],
        -- 1. Safely extract SALES_CENTER_NAME matching your criteria
        ISNULL((
            SELECT TOP 1 AC2.SALES_CENTER_NAME
            FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
            WHERE MONTH(AC2.REG_DATE) = @monthParam 
              AND YEAR(AC2.REG_DATE) = @yearParam
              AND AC2.SALES_CENTER_CODE = t.OUTLET_CODE
              AND AC2.SALES_CENTER_NAME IS NOT NULL
        ), 'No Name Registered') AS OUTLET_NAME,
        -- 2. Safely extract execution count
        (
            SELECT COUNT(*) 
            FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
            WHERE MONTH(AC2.REG_DATE) = @monthParam 
              AND YEAR(AC2.REG_DATE) = @yearParam
              AND AC2.SALES_CENTER_CODE = t.OUTLET_CODE
              AND AC2.JPJ_MODEL_DESCRIPTION LIKE '%' + t.[MODEL] + '%'
              --AND AC2.JPJ_MODEL_DESCRIPTION <> 'AXIA - 1000 E (MANUAL)'
        ) AS REG_COUNT
    FROM TargetData t
)
SELECT 
    ISNULL(a.[REGION], t.[REGION]) AS [REGION],
    ISNULL(a.OUTLET_CODE, t.OUTLET_CODE) AS OUTLET_CODE,
    ISNULL(a.OUTLET_NAME, 'No Name Registered') AS OUTLET_NAME,
    ISNULL(t.[MODEL], a.[MODEL]) AS [MODEL],
    ISNULL(t.TARGET_REG_COUNT, 0) AS TARGET_REG_COUNT,
    ISNULL(a.REG_COUNT, 0) AS ACTUAL_REG_COUNT,
    
    -- 1. No Decimal Places (rounded to nearest integer)
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT, 0) AS INT)
    END AS REG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,1))
    END AS REG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,2))
    END AS REG_PCTG_2

FROM TargetData t
FULL OUTER JOIN ActualData a 
    ON t.OUTLET_CODE = a.OUTLET_CODE AND t.[MODEL] = a.[MODEL]
ORDER BY REG_PCTG_2 DESC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        // To change 'Veh Br - ' to 'PSSB' 
        const updatedRecords = result.recordset.map(item => {
            if (item.OUTLET_NAME && item.OUTLET_NAME.startsWith('Veh Br-')) {
                return {
                    ...item,
                    OUTLET_NAME: item.OUTLET_NAME.replace('Veh Br-', 'PSSB ')
                };
            }
            return item;
        });

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_listModelOutlet Params: " + JSON.stringify(req.query));




        // Ori
        /* res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        }); */


        // Modified JSON
        res.status(200).json({
            success: true,
            count: updatedRecords.length,
            data: updatedRecords
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});



// List actual model monthly registration by month bu outlet
router.get('/api/registration/mnt_outletModelResult', authenticate, async (req, res) => {
    try {

        const { month, year, region, outletcode } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';
        const parsedOutletCode = outletcode || '522105';

        // console.log(parsedRegion);

        // To calculate query time taken
        const startTime = performance.now();

        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).input('outletCodeParam', parsedOutletCode).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        TR2.Model AS [MODEL],
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_REG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam 
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND TR2.[Outlet Code] = @outletCodeParam
      AND TR2.Model <> 'AXIA E'
    GROUP BY OTL2.Region_2, TR2.[Outlet Code], TR2.Model
),
ActualData AS (
    SELECT 
        t.[REGION],
        t.OUTLET_CODE,
        t.[MODEL],
        t.TARGET_REG_COUNT,
        (
            SELECT COUNT(*) 
            FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
            WHERE MONTH(AC2.REG_DATE) = @monthParam 
              AND YEAR(AC2.REG_DATE) = @yearParam
              AND AC2.SALES_CENTER_CODE = t.OUTLET_CODE
              AND AC2.JPJ_MODEL_DESCRIPTION LIKE '%' + t.[MODEL] + '%'
              --AND AC2.JPJ_MODEL_DESCRIPTION <> 'AXIA - 1000 E (MANUAL)'
        ) AS REG_COUNT
    FROM TargetData t
),
CalculatedData AS (
    SELECT 
        OUTLET_CODE,
        [MODEL],
        TARGET_REG_COUNT,
        REG_COUNT,
        CASE 
            WHEN TARGET_REG_COUNT = 0 THEN 0.0
            ELSE (REG_COUNT * 100.0) / TARGET_REG_COUNT
        END AS REG_PCTG
    FROM ActualData
),
SummaryData AS (
    SELECT 
        OUTLET_CODE, -- Hardcoded to match your WHERE filter cleanly
        COUNT(*) AS TOTAL_ROWS,
        SUM(CASE WHEN REG_PCTG < 50 THEN 1 ELSE 0 END) AS ROWS_BELOW_50,
        
        -- 0 Decimal Places (Rounded)
        CAST(ROUND(AVG(REG_PCTG), 0) AS INT) AS AVERAGE_REG_PCTG,
        
        -- 1 Decimal Place
        CAST(AVG(REG_PCTG) AS DECIMAL(10,1)) AS AVERAGE_REG_PCTG_1,
        
        -- 2 Decimal Places
        CAST(AVG(REG_PCTG) AS DECIMAL(10,2)) AS AVERAGE_REG_PCTG_2,
        
        (SELECT TOP 1 [MODEL] FROM CalculatedData ORDER BY REG_PCTG ASC, [MODEL] ASC) AS LOWEST_MODEL
        
    FROM CalculatedData
    GROUP BY OUTLET_CODE
)
-- Fetch the name exactly once at the end to keep query cost low
SELECT 
    s.OUTLET_CODE,
    ISNULL((
        SELECT TOP 1 AC2.SALES_CENTER_NAME
        FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
        WHERE MONTH(AC2.REG_DATE) = @monthParam  
          AND YEAR(AC2.REG_DATE) = @yearParam
          AND AC2.SALES_CENTER_CODE = s.OUTLET_CODE
          AND AC2.SALES_CENTER_NAME IS NOT NULL
    ), 'No Name Registered') AS OUTLET_NAME,
    s.TOTAL_ROWS,
    s.ROWS_BELOW_50,
    s.AVERAGE_REG_PCTG,
    s.AVERAGE_REG_PCTG_1,
    s.AVERAGE_REG_PCTG_2,
    s.LOWEST_MODEL
FROM SummaryData s;
`);
        //res.json(result.recordset);

        // Calculate the duration
        const duration = (performance.now() - startTime).toFixed(2)

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_outletModelResult Params: " + JSON.stringify(req.query));
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


// List actual monthly registration by month (Outlets)
router.get('/api/registration/mnt_RegionOutletSummary', authenticate, async (req, res) => {
    try {
        const { month, year, region } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';

        // console.log(parsedRegion);

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_REG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, TR2.[Outlet Code]
),
ActualData AS (
    SELECT 
        OTL2.Region_2 AS [REGION], 
        AC2.SALES_CENTER_CODE AS OUTLET_CODE, 
        AC2.SALES_CENTER_NAME AS OUTLET_NAME, 
        COUNT(*) AS REG_COUNT
    FROM DM_BRONZE.CRKPI.CRMDB_New_Car_Reg AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.REG_DATE) = @monthParam
      AND YEAR(AC2.REG_DATE) = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, AC2.SALES_CENTER_CODE, AC2.SALES_CENTER_NAME
),
DetailedResults AS (
    SELECT 
        ISNULL(a.[REGION], t.[REGION]) AS [REGION],
        ISNULL(a.OUTLET_CODE, t.OUTLET_CODE) AS OUTLET_CODE,
        ISNULL(a.OUTLET_NAME, 'No Name Registered') AS OUTLET_NAME,
        ISNULL(t.TARGET_REG_COUNT, 0) AS TARGET_REG_COUNT,
        ISNULL(a.REG_COUNT, 0) AS ACTUAL_REG_COUNT,
        CASE 
            WHEN ISNULL(t.TARGET_REG_COUNT, 0) = 0 THEN 0.00
            ELSE CAST((ISNULL(a.REG_COUNT, 0) * 100.0) / t.TARGET_REG_COUNT AS DECIMAL(10,2))
        END AS REG_PCTG_2
    FROM TargetData t
    FULL OUTER JOIN ActualData a 
        ON t.OUTLET_CODE = a.OUTLET_CODE
),
RankedResults AS (
    SELECT 
        OUTLET_CODE,
        OUTLET_NAME,
        REG_PCTG_2,
        COUNT(*) OVER() AS TOTAL_ROWS,
        AVG(CAST(REG_PCTG_2 AS FLOAT)) OVER() AS AVERAGE_REG_PCTG,
        SUM(CASE WHEN REG_PCTG_2 < 80.00 THEN 1 ELSE 0 END) OVER() AS ROWS_BELOW_50,
        ROW_NUMBER() OVER(ORDER BY REG_PCTG_2 DESC, ACTUAL_REG_COUNT DESC) AS RowNum
    FROM DetailedResults
)
SELECT 
    TOTAL_ROWS,
    ROWS_BELOW_50,
    
    -- 1. No Decimal Places (Rounded to nearest integer)
    CAST(ROUND(AVERAGE_REG_PCTG, 0) AS INT) AS AVERAGE_REG_PCTG,
    
    -- 2. One Decimal Place
    CAST(AVERAGE_REG_PCTG AS DECIMAL(10,1)) AS AVERAGE_REG_PCTG_1,
    
    -- 3. Two Decimal Places
    CAST(AVERAGE_REG_PCTG AS DECIMAL(10,2)) AS AVERAGE_REG_PCTG_2,
    
    OUTLET_CODE AS HIGHEST_OUTLET_CODE,
    OUTLET_NAME AS HIGHEST_OUTLET_NAME,
    REG_PCTG_2 AS HIGHEST_REG_PCTG
FROM RankedResults
WHERE RowNum = 1;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_RegionOutletSummary Params: " + JSON.stringify(req.query));
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


router.get('/api/dashboard/server_test', authenticate, async (req, res) => {
    try {
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().query(`SELECT COUNT(*) as 'total_reg_year'
    FROM [DM_BRONZE].[CRKPI].[CRMDB_New_Car_Reg]
    WHERE YEAR(REG_DATE) = '2025'`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/year_regActual");
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/year_regActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});



// Booking

router.get('/api/dashboard/mnt_bkgActual', authenticate, async (req, res) => {
    try {

        // 1. Get query parameters from the request URL
        const { month, year } = req.query;

        // Fallback defaults if parameters are missing from the URL call
        // const queryMonth = month || '05';
        // const queryYear = year || '2025';
        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        // To calculate query time taken
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`
SELECT 
    total_bkg_month_br,
    total_bkg_month_dlr,
    (total_bkg_month_br + total_bkg_month_dlr) AS total_bkg_month
FROM (
    SELECT 
        (SELECT COUNT(*) 
         FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Branch]
         WHERE BOOKING_STATUS = 'BOOK'
           AND MONTH(BOOKING_DATE) = @monthParam
           AND YEAR(BOOKING_DATE) = @yearParam) AS [total_bkg_month_br],
           
        (SELECT COUNT(*) 
         FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Dealer]
         WHERE MONTH(BOOKINGDATE) = @monthParam
           AND YEAR(BOOKINGDATE) = @yearParam) AS [total_bkg_month_dlr]
) AS [SourceData];
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2)


        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_bkgActual  Params: " + JSON.stringify(req.query));
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/mnt_bkgActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});



//booking target
router.get('/api/dashboard/mnt_bkgTarget2', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
                SELECT TO_NUMBER(sectionvalue) as target_bkg_month
                FROM bma_configuration_master
                WHERE configtype = 'BKG_TARGET'
                AND recordstatus = 'E'
                AND attr1 = :month
                AND attr2 = :year
            `,
            {
                month: parsedMonth,
                year: parsedYear
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_bkgTarget  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/dashboard/mnt_bkgTarget', authenticate, async (req, res) => {
    try {

        // 1. Get query parameters from the request URL
        const { month, year } = req.query;

        // Fallback defaults if parameters are missing from the URL call
        // const queryMonth = month || '05';
        // const queryYear = year || '2025';
        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        // To calculate query time taken
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`
SELECT ISNULL(SUM(Target), 0) as 'TARGET_BKG_MONTH'
FROM [DM_BRONZE].[CRKPI].[FlatFile_Target]
WHERE YEAR = @yearParam
  AND MONTH = @monthParam
  --AND REGION = 'C1'
  AND Parameter = 'Booking'
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2)


        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_bkgTarget  Params: " + JSON.stringify(req.query));
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/mnt_bkgTarget " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});


//booking List
router.get('/api/booking/mnt_ListActual', authenticate, async (req, res) => {
    try {

        // 1. Get query parameters from the request URL
        const { month, year } = req.query;

        // Fallback defaults if parameters are missing from the URL call
        // const queryMonth = month || '05';
        // const queryYear = year || '2025';
        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';

        // To calculate query time taken
        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_BKG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'Booking' 
      AND TR2.Month = @monthParam 
      AND TR2.Year = @yearParam
    GROUP BY OTL2.Region_2
),
ActualDataBr AS (
    SELECT OTL2.Region_2 AS [REGION],
           COUNT(*) AS ACTUAL_BKG_COUNT_BR
    FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Branch] AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.BOOKING_DATE) = @monthParam
      AND YEAR(AC2.BOOKING_DATE) = @yearParam
    GROUP BY OTL2.Region_2
),
ActualDataDlr AS (
    SELECT OTL2.Region_2 AS [REGION],
           COUNT(*) AS ACTUAL_BKG_COUNT_DLR
    FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Dealer] AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.COMPCODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.BOOKINGDATE) = @monthParam
      AND YEAR(AC2.BOOKINGDATE) = @yearParam
    GROUP BY OTL2.Region_2
)
SELECT 
    -- Resolves region across all three tables
    COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) AS [REGION],
    
    CASE COALESCE(t.[REGION], br.[REGION], dlr.[REGION])
        WHEN 'C1'  THEN 'Central 1'
        WHEN 'C2'  THEN 'Central 2'
        WHEN 'EC1' THEN 'East Coast 1'
        WHEN 'EC2' THEN 'East Coast 2'
        WHEN 'EM'  THEN 'East Malaysia'
        WHEN 'N'   THEN 'Northern'
        WHEN 'S'   THEN 'Southern'
        WHEN 'FMD' THEN 'FMD'
        ELSE COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) 
    END AS REGION_NAME,

    ISNULL(t.TARGET_BKG_COUNT, 0) AS TARGET_BKG_COUNT,
    ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) AS ACTUAL_BKG_COUNT_BR,
    ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0) AS ACTUAL_BKG_COUNT_DLR,
    
    -- Combined Total Actuals (Branch + Dealer)
    (ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) AS ACTUAL_BKG_COUNT,
    
    -- 1. No Decimal Places (rounded using combined actuals)
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT, 0) AS INT)
    END AS BKG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,1))
    END AS BKG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,2))
    END AS BKG_PCTG_2

FROM TargetData t
FULL OUTER JOIN ActualDataBr br 
    ON t.[REGION] = br.[REGION]
FULL OUTER JOIN ActualDataDlr dlr 
    ON COALESCE(t.[REGION], br.[REGION]) = dlr.[REGION]

ORDER BY 
    CASE WHEN COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) = 'FMD' THEN 1 ELSE 0 END ASC, 
    COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) ASC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2)


        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_bkgActual  Params: " + JSON.stringify(req.query));
        res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        });
    } catch (err) {
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/dashboard/mnt_bkgActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});

router.get('/api/booking/mnt_ListActualx', authenticate, async (req, res) => {
    let oracleConn;
    try {
        const { month, year } = req.query;

        // Maintain string versions for Oracle attributes and integers for MSSQL functions
        const stringMonth = month || '05';
        const stringYear = year || '2025';
        const intMonth = parseInt(stringMonth, 10);
        const intYear = parseInt(stringYear, 10);

        const startTime = performance.now();

        // ==========================================
        // STEP 1: FETCH TARGET DATA FROM ORACLE
        // ==========================================
        const oraclePool = await getOraclePool();
        oracleConn = await oraclePool.getConnection();
        const oracleResult = await oracleConn.execute(`
                SELECT 
                    attr3 as region_code, -- Assuming your ATTR3 contains the 'C1', 'C2' codes to map safely
                    TO_NUMBER(sectionvalue) as target_bkg_month
                FROM bma_configuration_master
                WHERE configtype = 'TGT_OUTLET'
                AND sectionname = 'BKG_TARGET_OUTLET'
                AND recordstatus = 'E'
                AND attr1 = :month
                AND attr2 = :year
            `,
            { month: stringMonth, year: stringYear },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await oracleConn.close();

        // ==========================================
        // STEP 2: FETCH ACTUAL DATA FROM MSSQL
        // ==========================================
        const mssqlPool = await getMssqlPool();
        const mssqlResult = await mssqlPool.request()
            .input('monthParam', intMonth)
            .input('yearParam', intYear)
            .query(`
WITH CombinedBookings AS (
    SELECT TR2.compcode AS center_code, OTL2.REGION_2
    FROM DM_BRONZE.crkpi.[CRMDB_Booking_Dealer] TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 ON TR2.compcode = OTL2.SLS_CODE 
    WHERE MONTH(TR2.BOOKINGDATE) = @monthParam AND YEAR(TR2.BOOKINGDATE) = @yearParam

    UNION ALL 

    SELECT ACT1.sales_center_code AS center_code, OTL2.REGION_2
    FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Branch] ACT1
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 ON ACT1.sales_center_code = OTL2.SLS_CODE 
    WHERE ACT1.BOOKING_STATUS = 'BOOK' AND MONTH(ACT1.BOOKING_DATE) = @monthParam AND YEAR(ACT1.BOOKING_DATE) = @yearParam
)
SELECT 
    REGION_2 as 'REGION',
    CASE REGION_2
        WHEN 'C1'  THEN 'Central 1'
        WHEN 'C2'  THEN 'Central 2'
        WHEN 'EC1' THEN 'East Coast 1'
        WHEN 'EC2' THEN 'East Coast 2'
        WHEN 'EM'  THEN 'East Malaysia'
        WHEN 'N'   THEN 'Northern'
        WHEN 'S'   THEN 'Southern'
        WHEN 'FMD' THEN 'FMD' 
        ELSE REGION_2
    END AS REGION_NAME,
    COUNT(center_code) AS 'ACTUAL_BKG_COUNT'
FROM CombinedBookings
GROUP BY REGION_2
ORDER BY 
    CASE WHEN REGION_2 = 'FMD' THEN 1 ELSE 0 END ASC, REGION_2 ASC;
`);

        // ==========================================
        // STEP 3: COMBINE DATA STREAMS & CALCULATE PERCENTAGES
        // ==========================================
        const combinedData = mssqlResult.recordset.map(mssqlRow => {
            // Find a match inside Oracle records (node-oracledb properties are UPPERCASE)
            const targetMatch = oracleResult.rows.find(
                oracleRow => oracleRow.REGION_CODE === mssqlRow.REGION
            );

            const targetValue = targetMatch ? targetMatch.TARGET_BKG_MONTH : 0;
            const actualValue = mssqlRow.ACTUAL_BKG_COUNT || 0;

            // Calculate percentage safely to prevent division by zero errors
            let percentage = 0;
            if (targetValue > 0) {
                percentage = (actualValue / targetValue) * 100;
            }

            return {
                ...mssqlRow,
                TARGET_BKG_COUNT: targetValue,
                // Fixed format outputs as strings based on your precision requirements
                BKG_PCTG: percentage.toFixed(0), // No decimal places
                BKG_PCTG_1: percentage.toFixed(1), // 1 decimal point
                BKG_PCTG_2: percentage.toFixed(2)  // 2 decimal points
            };
        });


        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/booking/mnt_ListActual  Params: " + JSON.stringify(req.query));

        res.status(200).json({
            success: true,
            count: combinedData.length,
            data: combinedData
        });

    } catch (err) {
        if (oracleConn) {
            try { await oracleConn.close(); } catch (e) { console.error(e); }
        }
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] failed: /api/booking/mnt_ListActual " + err.message);
        res.status(500).json({
            success: false,
            message: 'Database query execution failed cross-platform',
            error: err.message
        });
    }
});


router.get('/api/booking/mnt_ListActual_temp', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
SELECT 
    btd.region_2 AS region,
    CASE btd.region_2
        WHEN 'C1'  THEN 'Central 1'
        WHEN 'C2'  THEN 'Central 2'
        WHEN 'EC1' THEN 'East Coast 1'
        WHEN 'EC2' THEN 'East Coast 2'
        WHEN 'EM'  THEN 'East Malaysia'
        WHEN 'N'   THEN 'Northern'
        WHEN 'S'   THEN 'Southern'
        WHEN 'FMD' THEN 'FMD' 
        ELSE btd.region_2
    END AS region_name,
    TO_NUMBER(COUNT(*)) AS actual_bkg_count, 
    0 AS target_bkg_count, 
    '0' AS bkg_pctg, 
    '0.0' AS bkg_pctg_1, 
    '0.00' AS bkg_pctg_2
FROM ordermaster om, bma_temp_dealermaster btd
WHERE om.bookingdate >= '1-jul-2025'
  AND om.bookingdate < '1-aug-2025'
  AND orderstatus NOT IN ('NEW','VOID')
  AND om.compcode = btd.sls_code
  AND (1=1 or 1 = :month)
  AND (1=1 or 1 = :year)
GROUP BY 
    btd.region_2,
    CASE btd.region_2
        WHEN 'C1'  THEN 'Central 1'
        WHEN 'C2'  THEN 'Central 2'
        WHEN 'EC1' THEN 'East Coast 1'
        WHEN 'EC2' THEN 'East Coast 2'
        WHEN 'EM'  THEN 'East Malaysia'
        WHEN 'N'   THEN 'Northern'
        WHEN 'S'   THEN 'Southern'
        WHEN 'FMD' THEN 'FMD' 
        ELSE btd.region_2
    END
            `,
            {
                month: parsedMonth,
                year: parsedYear
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/dashboard/mnt_ListActual_temp  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/booking/mnt_ListActual_ora', authenticate, async (req, res) => {
    try {

        const { month, year } = req.query;
        const parsedMonth = month || '05';
        const parsedYear = year || '2025';

        const startDate = new Date(parsedYear, parsedMonth - 1, 1);
        const endDate = new Date(parsedYear, parsedMonth, 1); // Automatically wraps to next month

        // Call oracle date formatter
        const parsedStartDate = formatOracleDate(startDate); // "1-MAY-2025"
        const parsedEndDate = formatOracleDate(endDate);     // "1-JUN-2025"

        // console.log(parsedStartDate);
        // console.log(parsedEndDate);

        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
SELECT 
    region,
    region_name,
    SUM(actual_bkg_count) AS actual_bkg_count,
    SUM(target_bkg_count) AS target_bkg_count,
    0 AS bkg_pctg, 
    0.0 AS bkg_pctg_1, 
    0.00 AS bkg_pctg_2
FROM (
    -- QUERY 1: Branch
    SELECT 
        btd.region_2 AS region,
        CASE btd.region_2
            WHEN 'C1'  THEN 'Central 1'
            WHEN 'C2'  THEN 'Central 2'
            WHEN 'EC1' THEN 'East Coast 1'
            WHEN 'EC2' THEN 'East Coast 2'
            WHEN 'EM'  THEN 'East Malaysia'
            WHEN 'N'   THEN 'Northern'
            WHEN 'S'   THEN 'Southern'
            WHEN 'FMD' THEN 'FMD' 
            ELSE btd.region_2
        END AS region_name, 
        COUNT(*) AS actual_bkg_count,      
        0 AS target_bkg_count
    FROM sndsv_booking_details bdl, bma_temp_dealermaster btd
    --WHERE EXTRACT(YEAR FROM bdl.firmed_booking_date) = :year
    --  AND EXTRACT(MONTH FROM bdl.firmed_booking_date) = :month
    WHERE bdl.firmed_booking_date >= :startDate
      AND bdl.firmed_booking_date < :endDate
      AND bdl.booking_status NOT IN ('TB','CB','WAIT')
      AND bdl.sales_center_code = btd.sls_code
    GROUP BY btd.region_2

    UNION ALL

    -- QUERY 2: Dealer
    SELECT 
        btd.region_2 AS region,
        CASE btd.region_2
            WHEN 'C1'  THEN 'Central 1'
            WHEN 'C2'  THEN 'Central 2'
            WHEN 'EC1' THEN 'East Coast 1'
            WHEN 'EC2' THEN 'East Coast 2'
            WHEN 'EM'  THEN 'East Malaysia'
            WHEN 'N'   THEN 'Northern'
            WHEN 'S'   THEN 'Southern'
            WHEN 'FMD' THEN 'FMD' 
            ELSE btd.region_2
        END AS region_name,
        COUNT(*) AS actual_bkg_count, 
        0 AS target_bkg_count
    FROM ordermaster om, bma_temp_dealermaster btd
    -- WHERE EXTRACT(YEAR FROM om.bookingdate) = :year
      -- AND EXTRACT(MONTH FROM om.bookingdate) = :month
      -- AND EXTRACT(YEAR FROM om.orderdatetime) = :year
      -- AND EXTRACT(MONTH FROM om.orderdatetime) = :month
      WHERE om.bookingdate >= :startDate
      AND om.bookingdate < :endDate
      AND orderstatus NOT IN ('NEW','VOID')
      AND om.compcode = btd.sls_code
    GROUP BY btd.region_2
)
GROUP BY region, region_name
ORDER BY region
            `,
            {
                // month: parsedMonth,
                // year: parsedYear,
                startDate: parsedStartDate,
                endDate: parsedEndDate,
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/booking/mnt_ListActual_ora  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});


router.get('/api/booking/mnt_listRegionOutlet', authenticate, async (req, res) => {
    try {
        const { month, year, region } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';

        // console.log(parsedRegion);

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_BKG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'New Car Reg' 
      AND TR2.Month = @monthParam
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, TR2.[Outlet Code]
),
ActualDataBr AS (
    SELECT OTL2.Region_2 AS [REGION],
           OTL2.SLS_CODE AS OUTLET_CODE,
           OTL2.SLS_COMP_NAME AS OUTLET_NAME,
           COUNT(*) AS ACTUAL_BKG_COUNT_BR
    FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Branch] AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.BOOKING_DATE) = @monthParam
      AND YEAR(AC2.BOOKING_DATE) = @yearParam
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, OTL2.SLS_CODE, OTL2.SLS_COMP_NAME
),
ActualDataDlr AS (
    SELECT OTL2.Region_2 AS [REGION],
           OTL2.SLS_CODE AS OUTLET_CODE,
           OTL2.SLS_COMP_NAME AS OUTLET_NAME,
           COUNT(*) AS ACTUAL_BKG_COUNT_DLR
    FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Dealer] AC2
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON AC2.COMPCODE = OTL2.SLS_CODE 
    WHERE MONTH(AC2.BOOKINGDATE) = @monthParam
      AND YEAR(AC2.BOOKINGDATE) = @yearParam
      AND OTL2.REGION_2 = @regionParam
    GROUP BY OTL2.Region_2, OTL2.SLS_CODE, OTL2.SLS_COMP_NAME
)
SELECT 
    -- Resolves region and outlet attributes safely across targets and actuals
    COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) AS [REGION],
    COALESCE(t.OUTLET_CODE, br.OUTLET_CODE, dlr.OUTLET_CODE) AS OUTLET_CODE,
    COALESCE(br.OUTLET_NAME, dlr.OUTLET_NAME, 'No Name Registered') AS OUTLET_NAME,
    
    ISNULL(t.TARGET_BKG_COUNT, 0) AS TARGET_BKG_COUNT,
    ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) AS ACTUAL_BKG_COUNT_BR,
    ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0) AS ACTUAL_BKG_COUNT_DLR,

    -- Combined sum of branch and dealer bookings
    (ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) AS ACTUAL_BKG_COUNT,
    -- 1. No Decimal Places (rounded using combined total)
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT, 0) AS INT)
    END AS BKG_PCTG,
    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,1))
    END AS BKG_PCTG_1,
    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST(((ISNULL(br.ACTUAL_BKG_COUNT_BR, 0) + ISNULL(dlr.ACTUAL_BKG_COUNT_DLR, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,2))
    END AS BKG_PCTG_2
FROM TargetData t
FULL OUTER JOIN ActualDataBr br 
    ON t.OUTLET_CODE = br.OUTLET_CODE
FULL OUTER JOIN ActualDataDlr dlr 
    ON COALESCE(t.OUTLET_CODE, br.OUTLET_CODE) = dlr.OUTLET_CODE
ORDER BY BKG_PCTG_2 DESC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        // To change 'Veh Br - ' to 'PSSB' 
        const updatedRecords = result.recordset.map(item => {
            if (item.OUTLET_NAME && item.OUTLET_NAME.startsWith('Veh Br-')) {
                return {
                    ...item,
                    OUTLET_NAME: item.OUTLET_NAME.replace('Veh Br-', 'PSSB ')
                };
            }
            return item;
        });

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/booking/mnt_listRegionOutlet Params: " + JSON.stringify(req.query));




        // Ori
        /* res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        }); */


        // Modified JSON
        res.status(200).json({
            success: true,
            count: updatedRecords.length,
            data: updatedRecords
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});


/*
router.get('/api/booking/mnt_listRegionOutlet_ora',authenticate, async (req, res) => {
    try {

        const { month, year, region } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';
        const parsedRegion = region || 'C1';


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  btd.region_2 as region, sls_code as outlet_code, sls_comp_name as outlet_name,
        count(*)  AS actual_bkg_count, 0 as target_bkg_count, 0 as bkg_pctg, 0.0 as bkg_pctg_1, 0.00 as bkg_pctg_2
from ordermaster om, bma_temp_dealermaster btd
WHERE EXTRACT(YEAR FROM om.bookingdate) = :year
  AND EXTRACT(MONTH FROM om.bookingdate) = :month
  AND EXTRACT(YEAR FROM om.orderdatetime) = :year
  AND EXTRACT(MONTH FROM om.orderdatetime) = :month
  AND om.orderstatus NOT IN ('NEW','VOID')
  AND om.compcode = btd.sls_code
  AND btd.region_2 = :region
  GROUP BY btd.region_2, sls_code, sls_comp_name--, d.description
UNION
SELECT 
    btd.region_2 AS region, btd.sls_code as outlet_code, btd.sls_comp_name,
    COUNT(*) AS actual_bkg_count,      
    0 as target_bkg_count, 0 as bkg_pctg, 0.0 as bkg_pctg_1, 0.00 as bkg_pctg_2
FROM sndsv_booking_details bdl, bma_temp_dealermaster btd
WHERE EXTRACT(YEAR FROM bdl.firmed_booking_date) = :year
  AND EXTRACT(MONTH FROM bdl.firmed_booking_date) = :month
  AND bdl.booking_status NOT IN ('TB','CB','WAIT')
  AND bdl.sales_center_code = btd.sls_code
  AND btd.region_2 = :region
GROUP BY btd.region_2, sls_code, sls_comp_name
ORDER BY ACTUAL_BKG_COUNT DESC
            `,
            {
                month: parsedMonth,
                year: parsedYear,
                region: parsedRegion
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/booking/mnt_listRegionOutlet_ora  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});
*/

router.get('/api/booking/mnt_listModelOutlet', authenticate, async (req, res) => {
    try {
        const { month, year, region, outletcode } = req.query;

        const parsedMonth = parseInt(month, 10) || '05';
        const parsedYear = parseInt(year, 10) || '2025';
        const parsedRegion = region || 'C1';
        const parsedOutletCode = outletcode || '522105';

        // console.log(parsedRegion);

        const startTime = performance.now();
        const pool = await getMssqlPool();
        const result = await pool.request().input('monthParam', parseInt(parsedMonth))
            .input('yearParam', parseInt(parsedYear)).input('regionParam', parsedRegion).input('outletCodeParam', parsedOutletCode).query(`
WITH TargetData AS (
    SELECT 
        OTL2.Region_2 AS [REGION],
        TR2.[Outlet Code] AS OUTLET_CODE,
        TR2.Model AS [MODEL],
        SUM(TRY_CAST(TR2.Target AS INT)) AS TARGET_BKG_COUNT
    FROM DM_BRONZE.crkpi.FlatFile_Target TR2 
    JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 
        ON TR2.[Outlet Code] = OTL2.SLS_CODE 
    WHERE TR2.Parameter = 'Booking' 
      AND TR2.Month = @monthParam
      AND TR2.Year = @yearParam
      AND OTL2.OUTLET_ACTIVE = 'Active'
      AND TR2.[Outlet Code] = @outletCodeParam
      AND TR2.Model <> 'AXIA E'
    GROUP BY OTL2.Region_2, TR2.[Outlet Code], TR2.Model
),
ActualDataBr AS (
    SELECT 
        t.[REGION],
        t.OUTLET_CODE,
        t.[MODEL],
        ISNULL((
            SELECT TOP 1 OTL2.SLS_COMP_NAME
            FROM DM_GOLD.crkpi.OUTLET_TYPE OTL2
            WHERE OTL2.SLS_CODE = t.OUTLET_CODE
        ), 'No Name Registered') AS OUTLET_NAME,
        (
            SELECT COUNT(*) 
            FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Branch] AC2
            JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 ON AC2.SALES_CENTER_CODE = OTL2.SLS_CODE
            WHERE MONTH(AC2.BOOKING_DATE) = TRY_CAST(@monthParam AS INT)
              AND YEAR(AC2.BOOKING_DATE) = TRY_CAST(@yearParam AS INT)
              AND AC2.SALES_CENTER_CODE = t.OUTLET_CODE
              -- Modify or remove model matching rule below if your branch table uses a different column
            AND AC2.VML_MANUFACTURING_CODE IN (
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ'
                      WHEN 'ALZA' THEN 'BP5HZ'
                      WHEN 'AXIA' THEN 'CG1XZ'
                      WHEN 'BEZZA' THEN 'AQ1GZ2'
                      WHEN 'ARUZ' THEN 'W5XZ2'
                      WHEN 'ATIVA' THEN 'U1XZ'
                      WHEN 'TRAZ' THEN 'Y5XZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ1'
                      WHEN 'ALZA' THEN 'BP5VZ'
                      WHEN 'AXIA' THEN 'CG1SZ'
                      WHEN 'BEZZA' THEN 'AQ1GX2'
                      WHEN 'ARUZ' THEN 'W5VZ1'
                      WHEN 'ATIVA' THEN 'U1HZ'
                      WHEN 'TRAZ' THEN 'Y5HZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5XZ'
                      WHEN 'ALZA' THEN 'BP5XZ'
                      WHEN 'AXIA' THEN 'CG1GZ'
                      WHEN 'BEZZA' THEN 'AQ3XZ1'
                      WHEN 'ARUZ' THEN 'W5VZ2'
                      WHEN 'ATIVA' THEN 'U1VZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      WHEN 'AXIA' THEN 'CG1VZ'
                      WHEN 'BEZZA' THEN 'AQ3VZ1'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      ELSE 'UNKNOWN'
                  END
              )
        ) AS REG_COUNT
    FROM TargetData t
),
ActualDataDlr AS (
    SELECT 
        t.[REGION],
        t.OUTLET_CODE,
        t.[MODEL],
        ISNULL((
            SELECT TOP 1 OTL2.SLS_COMP_NAME
            FROM DM_GOLD.crkpi.OUTLET_TYPE OTL2
            WHERE OTL2.SLS_CODE = t.OUTLET_CODE
        ), 'No Name Registered') AS OUTLET_NAME,
        (
            SELECT COUNT(*) 
            FROM [DM_BRONZE].[CRKPI].[CRMDB_Booking_Dealer] AC2
            JOIN DM_GOLD.crkpi.OUTLET_TYPE OTL2 ON AC2.COMPCODE = OTL2.SLS_CODE
            WHERE MONTH(AC2.BOOKINGDATE) = TRY_CAST(@monthParam AS INT)
              AND YEAR(AC2.BOOKINGDATE) = TRY_CAST(@yearParam AS INT)
              AND AC2.COMPCODE = t.OUTLET_CODE
              -- Modify or remove model matching rule below if your dealer table uses a different column
            AND AC2.VML_MANUFACTURING_CODE IN (
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ'
                      WHEN 'ALZA' THEN 'BP5HZ'
                      WHEN 'AXIA' THEN 'CG1XZ'
                      WHEN 'BEZZA' THEN 'AQ1GZ2'
                      WHEN 'ARUZ' THEN 'W5XZ2'
                      WHEN 'ATIVA' THEN 'U1XZ'
                      WHEN 'TRAZ' THEN 'Y5XZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ1'
                      WHEN 'ALZA' THEN 'BP5VZ'
                      WHEN 'AXIA' THEN 'CG1SZ'
                      WHEN 'BEZZA' THEN 'AQ1GX2'
                      WHEN 'ARUZ' THEN 'W5VZ1'
                      WHEN 'ATIVA' THEN 'U1HZ'
                      WHEN 'TRAZ' THEN 'Y5HZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5XZ'
                      WHEN 'ALZA' THEN 'BP5XZ'
                      WHEN 'AXIA' THEN 'CG1GZ'
                      WHEN 'BEZZA' THEN 'AQ3XZ1'
                      WHEN 'ARUZ' THEN 'W5VZ2'
                      WHEN 'ATIVA' THEN 'U1VZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      WHEN 'AXIA' THEN 'CG1VZ'
                      WHEN 'BEZZA' THEN 'AQ3VZ1'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      ELSE 'UNKNOWN'
                  END
              )
        ) AS REG_COUNT
    FROM TargetData t
)
SELECT 
    COALESCE(t.[REGION], br.[REGION], dlr.[REGION]) AS [REGION],
    COALESCE(t.OUTLET_CODE, br.OUTLET_CODE, dlr.OUTLET_CODE) AS OUTLET_CODE,
    COALESCE(br.OUTLET_NAME, dlr.OUTLET_NAME, 'No Name Registered') AS OUTLET_NAME,
    COALESCE(t.[MODEL], br.[MODEL], dlr.[MODEL]) AS [MODEL],
    
    ISNULL(t.TARGET_BKG_COUNT, 0) AS TARGET_BKG_COUNT,
    ISNULL(br.REG_COUNT, 0) AS ACTUAL_BKG_COUNT_BR,
    ISNULL(dlr.REG_COUNT, 0) AS ACTUAL_BKG_COUNT_DLR,
    
    -- Combined Branch + Dealer booking counts
    (ISNULL(br.REG_COUNT, 0) + ISNULL(dlr.REG_COUNT, 0)) AS ACTUAL_BKG_COUNT,
    
    -- 1. No Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0
        ELSE CAST(ROUND(((ISNULL(br.REG_COUNT, 0) + ISNULL(dlr.REG_COUNT, 0)) * 100.0) / t.TARGET_BKG_COUNT, 0) AS INT)
    END AS BKG_PCTG,

    -- 2. One Decimal Place
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.0
        ELSE CAST(((ISNULL(br.REG_COUNT, 0) + ISNULL(dlr.REG_COUNT, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,1))
    END AS BKG_PCTG_1,

    -- 3. Two Decimal Places
    CASE 
        WHEN ISNULL(t.TARGET_BKG_COUNT, 0) = 0 THEN 0.00
        ELSE CAST(((ISNULL(br.REG_COUNT, 0) + ISNULL(dlr.REG_COUNT, 0)) * 100.0) / t.TARGET_BKG_COUNT AS DECIMAL(10,2))
    END AS BKG_PCTG_2

FROM TargetData t
FULL OUTER JOIN ActualDataBr br 
    ON t.OUTLET_CODE = br.OUTLET_CODE AND t.[MODEL] = br.[MODEL]
FULL OUTER JOIN ActualDataDlr dlr 
    ON COALESCE(t.OUTLET_CODE, br.OUTLET_CODE) = dlr.OUTLET_CODE 
   AND COALESCE(t.[MODEL], br.[MODEL]) = dlr.[MODEL]

ORDER BY BKG_PCTG_2 DESC;
`);
        //res.json(result.recordset);
        const duration = (performance.now() - startTime).toFixed(2);

        // To change 'Veh Br - ' to 'PSSB' 
        const updatedRecords = result.recordset.map(item => {
            if (item.OUTLET_NAME && item.OUTLET_NAME.startsWith('Veh Br-')) {
                return {
                    ...item,
                    OUTLET_NAME: item.OUTLET_NAME.replace('Veh Br-', 'PSSB ')
                };
            }
            return item;
        });

        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/registration/mnt_listModelOutlet Params: " + JSON.stringify(req.query));




        // Ori
        /* res.status(200).json({
            success: true,
            count: result.recordset.length,
            data: result.recordset
        }); */


        // Modified JSON
        res.status(200).json({
            success: true,
            count: updatedRecords.length,
            data: updatedRecords
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Database query execution failed',
            error: err.message
        });
    }

});


/*
router.get('/api/booking/mnt_listModelOutlet_ora',authenticate, async (req, res) => {
    try {

        const { month, year, outletcode } = req.query;

        const parsedMonth = month || '05';
        const parsedYear = year || '2025';
        const parsedOutletcode = outletcode || '522105';

        const startDate = new Date(parsedYear, parsedMonth - 1, 1);
        const endDate = new Date(parsedYear, parsedMonth, 1);

        // Call oracle date formatter
        const parsedStartDate = formatOracleDate(startDate); // "1-MAY-2025"
        const parsedEndDate = formatOracleDate(endDate);     // "1-JUN-2025"


        const startTime = performance.now();
        const pool = await getOraclePool();   // pool object
        const conn = await pool.getConnection();
        const result = await conn.execute(`
select  btd.region_2 as region, sls_code as outlet_code, sls_comp_name as outlet_name,
        TRIM(REGEXP_REPLACE(d.description, 'PERODUA|\(NEW\)', '', 1, 0, 'i')) AS model, 
        count(*)  AS actual_bkg_count, 0 as target_bkg_count, 0 as bkg_pctg, 0.0 as bkg_pctg_1, 0.00 as bkg_pctg_2
from ordermaster om, bma_temp_dealermaster btd,
        dna.sndsd_family_model_colors a, dna.sndsd_vehicle_colors b, dna.sndsd_family_models c, dna.sndsd_vehicle_family_groups d, dna.sndsd_vehicle_families e 
WHERE om.bookingdate >= :startDate
  AND om.bookingdate < :endDate
  AND om.orderstatus NOT IN ('NEW','VOID')
  AND om.compcode = btd.sls_code
  AND om.fmrid = a.id
  AND a.vcl_code = b.vcl_code
  AND a.fml_id = c.id
  AND e.vfp_id = d.id
  AND c.vfy_id = e.id 
  --AND d.description like '%AXIA%'
  AND d.code not in ('D87A')  --remove AXIA Rahmah (D87A)
  AND om.compcode = :outletcode
  GROUP BY btd.region_2, sls_code, sls_comp_name, d.description
--  ORDER BY actual_bkg_count DESC
UNION
SELECT  btd.region_2 as region, sls_code as outlet_code, sls_comp_name as outlet_name,
        TRIM(REGEXP_REPLACE(d.description, 'PERODUA|\\(NEW\\)', '', 1, 0, 'i')) AS model, 
        count(*)  AS actual_bkg_count, 0 as target_bkg_count, 0 as bkg_pctg, 0.0 as bkg_pctg_1, 0.00 as bkg_pctg_2
FROM    sndsv_booking_details bdl, bma_temp_dealermaster btd, dna.sndsd_family_model_colors a, dna.sndsd_vehicle_colors b,
        dna.sndsd_family_models c, dna.sndsd_vehicle_family_groups d, dna.sndsd_vehicle_families e 
WHERE bdl.sales_center_code = :outletcode
AND bdl.sales_center_code = btd.sls_code
AND bdl.booking_status = 'BOOK'
AND bdl.firmed_booking_date >= :startDate
AND bdl.firmed_booking_date < :endDate
AND bdl.booking_status NOT IN ('TB','CB','WAIT')
AND bdl.fmr_id = a.id
AND a.fml_id = c.id
AND e.vfp_id = d.id
AND c.vfy_id = e.id 
--AND d.description like '%AXIA%'
AND d.code not in ('D87A')  --remove AXIA Rahmah (D87A)
GROUP BY btd.region_2, sls_code, sls_comp_name, d.description
ORDER BY actual_bkg_count DESC
            `,
            {
                // month: parsedMonth,
                // year: parsedYear,
                outletcode: parsedOutletcode,
                startDate: parsedStartDate,
                endDate: parsedEndDate,
            },
            { outFormat: oracledb.OUT_FORMAT_OBJECT }
        );
        await conn.close();
        const duration = (performance.now() - startTime).toFixed(2);
        console.log("[" + new Date().toISOString().replace('T', ' ').substring(0, 19) + "] success (" + duration + "ms): /api/booking/mnt_listModelOutlet_ora  Params: " + JSON.stringify(req.query));

        //res.json(result.rows);
        res.status(200).json({
            success: true,
            count: result.rows.length,
            data: result.rows
        });
    } catch (err) {
        console.error('Oracle error:', err);
        res.status(500).json({ error: err + '. Oracle query failed' });
    }
});
*/


// end BMA (PRIME-GO) query

module.exports = router;