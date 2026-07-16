const { Pool } = require("pg");
const { db: dbConfig } = require("./app");

const pool = new Pool(dbConfig);

module.exports = pool;
