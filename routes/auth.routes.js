const express = require("express");
const router = express.Router();
const User = require("../models/User.model");
const mongoose = require("mongoose");

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

  // make sure users fill all mandatory fields:
  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
    });
    return;
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render("auth/signup", {
      errorMessage:
        "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
    return;
  }
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
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else if (error.code === 11000) {
        console.log(
          " Username and email need to be unique. Either username or email is already used. "
        );

        res.status(500).render("auth/signup", {
          errorMessage:
            "Username/email already in use and/or incorrect password.",
        });
      } else {
        next(error);
      }
    });
});

//GET INFO TO DISPLAY USER PROFILE
router.get("/userProfile", (req, res) => res.render("users/user-profile"));

module.exports = router;
