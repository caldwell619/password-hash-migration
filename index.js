const AWS = require('aws-sdk-mock');
const bcrypt = require('bcrypt');
const oldSaltRounds = 4;
const newSaltRounds = 10;
const oldHash = '$2b$04$pdxtPIgQ4WRpBdotuJmJw.bu8ud9VFNR2TQ9z/u//JiJzXQCkrDjK';
const newHash = '$2b$10$WRYwKxRSLUhsPs9P0ilgh.rOEzOqrnCfigfPsN2d.4iB0OBpehWyS';
const plainTextPassword = 'password';
const user = {
  Username: 'username',
  Password: oldHash
};

exports.login = async event => {
  const givenPassword = event.body.Password
  const dbUser = await mockUserFetch(event.body.Username);
  const validPassword = await isValidPassword(givenPassword, dbUser.Password)
  return validPassword ? 
    await returnUserWithCurrentSalt(givenPassword, oldSaltRounds, newSaltRounds, dbUser) : 
      false
}

const hashPassword = async (plainTextPassword, saltRounds) => (
  await bcrypt.hash(plainTextPassword, saltRounds)
);

const isOldSalt = (hash, oldSaltRounds) => (
  parseInt(hash.substring(4, 6)) === oldSaltRounds
);

const calculateSaltRounds = hash => parseInt(hash.substring(4, 6))

const isValidPassword = async (plainTextPassword, dbHashPassword) => (
   await bcrypt.compare(plainTextPassword, dbHashPassword)
);

const mockUserFetch = async username => {
  const user = await AWS.mock('DynamoDB', 'getItem', {
    Username: username,
    Password: oldHash
  });
  return user.replace
}
const mockPasswordUpdate = async (username, hash) => {
  const user = await AWS.mock('DynamoDB', 'putItem', {
    Username: username,
    Password: hash
  });
  return user.replace
}

const returnUserWithCurrentSalt = async (plainTextPassword, oldSaltRounds, newSaltRounds, dbUser) => {
  if (isOldSalt(dbUser.Password, oldSaltRounds)) {
    const hash = await hashPassword(plainTextPassword, newSaltRounds);
    return await mockPasswordUpdate(dbUser.Username, hash)
  } else {
    return dbUser
  }
}


exports.hashPassword = hashPassword;
exports.isOldSalt = isOldSalt;
exports.isValidPassword = isValidPassword;
exports.returnUserWithCurrentSalt = returnUserWithCurrentSalt;
exports.calculateSaltRounds = calculateSaltRounds;