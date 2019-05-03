const AWS = require('aws-sdk-mock');

// old rounds to be replaced with environment variable
const oldSaltRounds = 4;
const newSaltRounds = 10;
const plainTextPassword = 'password';
const username = 'username';
const oldHash = '$2b$04$pdxtPIgQ4WRpBdotuJmJw.bu8ud9VFNR2TQ9z/u//JiJzXQCkrDjK';
const newHash = '$2b$10$WRYwKxRSLUhsPs9P0ilgh.rOEzOqrnCfigfPsN2d.4iB0OBpehWyS';
const oldPasswordUser = {
  Username: username,
  Password: oldHash
}
const newPasswordUser = {
  Username: username,
  Password: newHash
}
const oldPasswordEvent = {
  body: {
    Username: 'username',
    Password: 'password'
  }
}
const invalidEvent = {
  body: {
    Username: 'username',
    Password: 'incorrectPassword'
  }
}
const newPasswordEvent = {
  body: {
    Username: 'username',
    Password: 'password'
  }
}

// importing functions
const { hashPassword } = require('../index');
const { isOldSalt } = require('../index');
const { calculateSaltRounds } = require('../index');
const { isValidPassword } = require('../index');
const { returnUserWithCurrentSalt } = require('../index');
const { login } = require('../index');


describe('Updating password salt rounds', () => {
  test('Sanity Test', () => {
    expect(1).toBe(1);
  })
  test('old hash returns the correct number of salt rounds', () => {
    expect(calculateSaltRounds(oldHash)).toBe(oldSaltRounds)
  })
  test('new hash returns the correct number of salt rounds', () => {
    expect(calculateSaltRounds(newHash)).toBe(newSaltRounds)
  })
  test('plain text password returns hash', async () => {
    const hash = await hashPassword(plainTextPassword, oldSaltRounds);
    expect(hash).not.toBe(plainTextPassword)
  })
  test('old hash given to detection returns true', () => {
    expect(isOldSalt(oldHash, oldSaltRounds)).toBe(true)
  })
  test('new hash given to detection returns false', () => {
    expect(isOldSalt(newHash, oldSaltRounds)).toBe(false)
  })
  test('old, correct, password returns success', () => {
    isValidPassword(plainTextPassword, oldHash).then(result => {
      expect(result).toBe(true)
    })
  })
  test('old, incorrect, password returns success', () => {
    isValidPassword('incorrectPassword', oldHash).then(result => {
      expect(result).toBe(false)
    })
  })
  // begin integration tests
  test('old, correct password returns update with new hash with new salt rounds', async () => {
    const updatedUser = await returnUserWithCurrentSalt(plainTextPassword, oldSaltRounds, newSaltRounds, oldPasswordUser);
    expect(calculateSaltRounds(updatedUser.Password)).toBe(newSaltRounds);
  })
  test('new, correct password returns user', async () => {
    const updatedUser = await returnUserWithCurrentSalt(plainTextPassword, oldSaltRounds, newSaltRounds, newPasswordUser);
    expect(updatedUser).toBe(newPasswordUser)
  })
  test('old user returns user with updated salt rounds password', async () => {
    const updatedUser = await login(oldPasswordEvent);
    expect(calculateSaltRounds(updatedUser.Password)).toBe(newSaltRounds)
  })
  test('invalid password returns invalid message', async () => {
    const updatedUser = await login(invalidEvent);
    expect(updatedUser).toBe(false)
  })
})