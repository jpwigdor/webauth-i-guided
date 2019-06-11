const bcrypt = require("bcryptjs"); // <<<<<<<<<<<<< yarn add bcryptjs
const Users = require("../users/users-model.js");

function protected(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    console.log("Im in Protected-Middleware");
    Users.findBy({ username })
      .first()
      .then(user => {
        //
        if (user && bcrypt.compareSync(password, user.password)) {
          // password=the entered password. // user.password = hash within the db.sss
          next();
        } else {
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(400).json({ message: "please provide credentials" });
  }
}

module.exports = protected;