const express = require("express");
const router = express.Router();
const User = require("../models/User.model");

const bcryptjs = require("bcryptjs");
const saltRounds = 10;

/* GET home page */
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

//POST Route
router.post("/signup", (req, res, next) => {
  //console.log("The form data ", req.body);
  const { username, email, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        // username: username
        username,
        email,
        // passwordHash => this is the key from the User model
        //     ^
        //     |            |--> this is placeholder (how we named returning value from the previous method (.hash()))
        password: hashedPassword,
      });
    })
    .then((userFromDB) => {
      // console.log('Newly created user is: ', userFromDB);
      res.redirect("/userProfile");
    })
    .catch((error) => next(error));
});

//GET INFO TO DISPLAY USER PROFILE
router.get("/userProfile", (req, res) => res.render("users/user-profile"));

module.exports = router;
