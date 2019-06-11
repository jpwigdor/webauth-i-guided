const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // <<<<<<<<<<<<< yarn add bcryptjs

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");
const protected = require("./auth/protected-middleware");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  // check for username and password

  const hash = bcrypt.hashSync(user.password, 10); // 2^10 rounds
  // password -> hash it -> hash = 1 round -> hash it -> hash = 2 rounds
  // has the password
  user.password = hash; // <<<<<<<<<<<<<<<<<<<<<<

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  // we compare the password guess against the database hash.
  Users.findBy({ username })
    .first()
    .then(user => {
      //
      if (user && bcrypt.compareSync(password, user.password)) {
        // password=the entered password. // user.password = hash within the db.sss
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// protect this route, users must provide valid credentials to see the list of users
server.get("/api/users", protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
