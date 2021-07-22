const bcrypt = require('bcryptjs');
const password = "123456"
const hashedPassword = "$2a$10$FBuJNDJXbZ6uFsC5k.EpOeD6UG6O5hl4i/Rf7/5mmOiTiU.vUGUNy"
async function hashIt(password){
  const salt = await bcrypt.genSalt(6);
  const hashed = await bcrypt.hash(password, salt);
}
hashIt(password);
// compare the password user entered with hashed pass.
async function compareIt(password){
  const validPassword = await bcrypt.compare(password, hashedPassword);
  console.log(validPassword)
}
compareIt(password);