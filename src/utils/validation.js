const SAFE_TEMPLATES = new Set(["clean", "age_gate"]);
const PARAM_TOKEN_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const SHORT_CODE_RE = /^[a-z0-9_-]{3,80}$/;
const COUNTRY_RE = /^[A-Z]{2}$/;

const normalizeDomainUrl = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  const withoutProtocol = raw.replace(/^https?:\/\//, "");
  const hostname = withoutProtocol.split("/")[0].split("?")[0];
  if (
    !hostname ||
    hostname.length > 253 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname)
  ) {
    throw new Error("Domain khong hop le");
  }
  return hostname;
};

const normalizeSafeTemplate = (value) => {
  const template = String(value || "clean").trim().toLowerCase();
  if (!SAFE_TEMPLATES.has(template)) return "clean";
  return template;
};

const normalizeTargetUrl = (value) => {
  const raw = String(value || "").trim();
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (e) {
    throw new Error("Target URL khong hop le");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Target URL phai la http/https");
  }
  return parsed.toString();
};

const validateParamKey = (value) => {
  const key = String(value || "").trim();
  if (!PARAM_TOKEN_RE.test(key)) throw new Error("Param key khong hop le");
  return key;
};

const validateParamValue = (value) => {
  const paramValue = String(value || "").trim();
  if (!PARAM_TOKEN_RE.test(paramValue))
    throw new Error("Param value khong hop le");
  return paramValue;
};

const normalizeShortCode = (value) => {
  const code = String(value || "").trim().toLowerCase();
  if (!SHORT_CODE_RE.test(code)) {
    throw new Error("Ma rut gon chi gom a-z, 0-9, dau gach ngang/gach duoi va dai 3-80 ky tu");
  }
  return code;
};

const parseRules = (rulesInput) => {
  let parsed = [];
  if (Array.isArray(rulesInput)) {
    parsed = rulesInput;
  } else if (typeof rulesInput === "string" && rulesInput.trim()) {
    try {
      parsed = JSON.parse(rulesInput);
    } catch (e) {
      throw new Error("Rules khong hop le");
    }
  }

  if (!Array.isArray(parsed)) throw new Error("Rules khong hop le");

  return parsed.map((rule) => {
    const key = validateParamKey(rule?.key);
    const operator = String(rule?.operator || "").trim();
    if (!["exists", "equals"].includes(operator)) {
      throw new Error("Rule operator khong hop le");
    }
    const value =
      operator === "equals" ? String(rule?.value || "").trim() : "";
    if (operator === "equals" && !value) {
      throw new Error("Rule equals can gia tri");
    }
    if (value.length > 500) throw new Error("Rule value qua dai");
    return { key, operator, value };
  });
};

const normalizeCountries = (value) => {
  const rawValues = Array.isArray(value)
    ? value
    : typeof value === "string" && value.trim()
    ? value.split(",")
    : [];
  const countries = [...new Set(rawValues.map((item) => String(item).trim().toUpperCase()).filter(Boolean))];
  if (countries.some((item) => !COUNTRY_RE.test(item))) {
    throw new Error("Country filter khong hop le");
  }
  return countries;
};

const buildFilters = (allowedCountries) => {
  const countries = normalizeCountries(allowedCountries);
  return countries.length ? { countries } : {};
};

const validateName = (value, field = "Ten") => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${field} khong duoc de trong`);
  if (normalized.length > 150) throw new Error(`${field} qua dai`);
  return normalized;
};

module.exports = {
  SAFE_TEMPLATES,
  buildFilters,
  normalizeCountries,
  normalizeDomainUrl,
  normalizeSafeTemplate,
  normalizeShortCode,
  normalizeTargetUrl,
  parseRules,
  validateName,
  validateParamKey,
  validateParamValue,
};
