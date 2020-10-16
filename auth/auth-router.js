const router = require('express').Router();
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken')

const config = require("../api/config");
const {isValid} = require ('./auth-service')
const Users = require('./auth-model')

router.post('/register', (req, res) => {
  const credentials = req.body;

  if (isValid(credentials)) {
    const rounds = process.env.HASH_ROUNDS || 6;
    const hash = bcryptjs.hashSync(credentials.password, rounds);
    credentials.password = hash;

    Users.add(credentials)
      .then((user) => {
        res.status(201).json({ data: user });
      })
      .catch((err) => {
        res.status(500).json({ message: err.message });
      });
  } else {
    res.status(400).json({
      message:
        "Please provide username & password. The password should be alphanumeric.",
    });
  }
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (isValid(req.body)) {
    Users.findBy({ username: username })
      .then(([user]) => {
        if (user && bcryptjs.compareSync(password, user.password)) {
          const token = getJwt(user);

          res.status(200).json({ message: "Welcome to our API", token });
        } else {
          res.status(401).json({ message: "Invalid credentials" });
        }
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "Please provide username & password. The password should be alphanumeric.",
    });
  }
});

function getJwt(user) {
  const payload = {
    username: user.username,
  }
  const jwtOptions = {
    expiresIn: "8hr",
  }
  return jwt.sign(payload, config.jwtSecret, jwtOptions)
}

module.exports = router;
