const crypto = require("crypto");

// generating hash and salt and secure password
function genPassword(password) {
  const salt = crypto.randomBytes(32).toString("hex");
  const genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

  console.log("gensalt:", salt, "genHash:", genHash);

  return {
    salt: salt,
    hash: genHash,
  };
}

// password: user just provided us && salt: was in the db for that user record  hash: from db belongs to user who registered
// validating just entered password is the same as stored to db when user registered
// this will return true or false
function validPassword(password, hash, salt) {
  const hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

  return hash === hashVerify;
}

module.exports.validPassword = validPassword;
module.exports.genPassword = genPassword;
