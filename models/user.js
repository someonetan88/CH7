const bcrypt = require("bcryptjs");
const users = [];

function findUserByEmail(email) {
  return users.find((user) => user.email === email);
}

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

function updateUserPassword(email, hashedPassword) {
  const user = findUserByEmail(email);
  if (user) {
    user.password = hashedPassword;
  }
}

module.exports = {
  users,
  findUserByEmail,
  hashPassword,
  updateUserPassword,
};
