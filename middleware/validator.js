// middleware/validator.js
const Joi = require('joi');

// Define rules for GET requests running pagination or limits
const querySchema = Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10), // 🟢 Prevents pulling too many rows at once
    year: Joi.number().integer(),
    month: Joi.number().integer(),
    region: Joi.string().alphanum().max(5).trim(),
    outletcode: Joi.number().integer(),
    username: Joi.string().alphanum().max(5).trim(),
}).unknown(false); // 🔴 Blocks unexpected/unknown query parameters entirely

const validateQueryParams = (req, res, next) => {
    const { error, value } = querySchema.validate(req.query, { abortEarly: false });

    if (error) {
        return res.status(400).json({
            success: false,
            message: "Validation Failure: Malformed query parameters detected.",
            details: error.details.map(d => d.message)
        });
    }

    // Replace the raw query data with clean, validated, and cast values
    req.query = value;
    next();
};

module.exports = { validateQueryParams };