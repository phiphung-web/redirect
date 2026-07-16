const bcrypt = require("bcryptjs");
const db = require("../config/db");

const isBcryptHash = (value) => /^\$2[aby]\$\d+\$/.test(String(value || ""));

const hashPassword = async (password) => bcrypt.hash(String(password || ""), 10);

const verifyPasswordWithLazyMigration = async (user, password) => {
  const storedPassword = String(user?.password_hash || "");
  const plainPassword = String(password || "");
  const bcryptHash = isBcryptHash(storedPassword);
  const isValid = bcryptHash
    ? await bcrypt.compare(plainPassword, storedPassword)
    : plainPassword === storedPassword;

  if (!isValid) return { isValid: false, user };

  if (!bcryptHash && user?.id) {
    const nextHash = await hashPassword(plainPassword);
    await db.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [
      nextHash,
      user.id,
    ]);
    return { isValid: true, user: { ...user, password_hash: nextHash } };
  }

  return { isValid: true, user };
};

module.exports = {
  hashPassword,
  isBcryptHash,
  verifyPasswordWithLazyMigration,
};
