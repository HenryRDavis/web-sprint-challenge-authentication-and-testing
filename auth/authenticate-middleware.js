/* 
  complete the middleware code to check if the user is logged in
  before granting access to the next middleware/route handler
*/
const jwt = require("jsonwebtoken");

const config = require("../api/config");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, config.jwtSecret, (err, decodedToken) => {
      if (err) {
        res.status(401).json({ message: err.message });
      } else {
        req.jwt = decodedToken;

        next();
      }
    });
  } else{res.status(401).json({ you: 'shall not pass!' })
    }
};
