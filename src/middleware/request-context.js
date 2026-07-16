const crypto = require("crypto");

const requestContext = (req, res, next) => {
  const headerId = req.get("x-request-id");
  const requestId =
    headerId && String(headerId).trim()
      ? String(headerId).trim()
      : crypto.randomUUID();

  req.requestId = requestId;
  res.locals.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  next();
};

module.exports = { requestContext };
