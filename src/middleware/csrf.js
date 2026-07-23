const crypto = require("node:crypto");

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const TOKEN_BYTES = 32;

const ensureToken = (req) => {
  if (!req.session) {
    throw new Error("Session middleware must run before CSRF protection");
  }
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(TOKEN_BYTES).toString("base64url");
  }
  return req.session.csrfToken;
};

const safeEqual = (left, right) => {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  return (
    leftBuffer.length === rightBuffer.length &&
    leftBuffer.length > 0 &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  );
};

const csrfProtection = (req, _res, next) => {
  let expected;
  try {
    expected = ensureToken(req);
  } catch (error) {
    return next(error);
  }

  req.csrfToken = () => expected;
  if (SAFE_METHODS.has(req.method)) return next();

  const submitted =
    req.body?._csrf ||
    req.get("x-csrf-token") ||
    req.get("x-xsrf-token") ||
    "";
  if (safeEqual(submitted, expected)) return next();

  const error = new Error("Invalid CSRF token");
  error.code = "EBADCSRFTOKEN";
  return next(error);
};

module.exports = {
  csrfProtection,
  ensureToken,
  safeEqual,
};
