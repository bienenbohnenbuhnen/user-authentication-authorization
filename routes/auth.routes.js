const express = require("express");
const router = express.Router();
const User = require("../models/User.model");
const mongoose = require("mongoose");
const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard.js");

const bcryptjs = require("bcryptjs");
const saltRounds = 10;

/* GET home page */
router.get("/signup", isLoggedOut, (req, res, next) => {
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

//LOGIN METHOD//

// GET route ==> to display the login form to users
router.get("/login", isLoggedOut, (req, res) => res.render("auth/login"));

// POST login route ==> to process form data
router.post("/login", (req, res, next) => {
  console.log("SESSION =====> ", req.session);
  const { email, password } = req.body;

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }

  User.findOne({ email }) // <== check if there's user with the provided email
    .then((user) => {
      // <== "user" here is just a placeholder and represents the response from the DB
      if (!user) {
        // <== if there's no user with provided email, notify the user who is trying to login
        console.log("Email not registered. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
        return;
      }
      // if there's a user, compare provided password
      // with the hashed password saved in the database
      else if (bcryptjs.compareSync(password, user.password)) {
        // if the two passwords match, render the user-profile.hbs and
        //                   pass the user object to this view
        //                                 |
        //******* SAVE THE USER IN THE SESSION ********//
        req.session.currentUser = user;
        res.redirect("/userProfile");
      } else {
        // if the two passwords DON'T match, render the login form again
        // and send the error message to the user
        console.log("Incorrect password. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
      }
    })
    .catch((error) => next(error));
});

//GET INFO TO DISPLAY USER PROFILE
router.get("/userProfile", isLoggedIn, (req, res) => {
  res.render("users/user-profile", { userInSession: req.session.currentUser });
});

//LOG THE USER OUT
router.post("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) next(err);
    res.redirect("/");
  });
});

module.exports = router;
