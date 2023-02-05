const path = require("path");
const passportLocalMongoose = require("passport-local-mongoose");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const express = require("express");
const passport = require("passport");
const bodyParser = require("body-parser");
const LocalStrategy = require("passport-local");
const User = require("./models/user");
const fullName = require("fullname");

// Required for connection to the MongoDB cloud
require("dotenv").config({ path: "mongodb.env" });
const dotenv = require("dotenv");

dotenv.config();
const dbPath = process.env.DB_PATH;

if (!dbPath) {
  console.error(
    "Error: No database path found in environment variables. Make sure to set the DB_PATH variable in your .env file."
  );
  process.exit(1);
}

// Start fullname
(async () => {
  console.log(await fullName());
})();

var app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
});

UserSchema.plugin(passportLocalMongoose);

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

module.exports = User;

// middleware functions that use UserSchema and User go here
app.use(
  require("express-session")({
    secret: "Rusty is a dog",
    resave: false,
    saveUninitialized: false,
  })
);

mongoose.connect(dbPath, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on("connected", () => {
  console.log("MongoDB connected successfully!");
});

mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err);
});

//

app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, "views/css")));
app.use(express.static("views"));

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.roles === "admin") {
    return res.redirect("/secret_admin", { username: req.user.username });
  } else {
    return res.redirect("/secret", { username: req.user.username });
  }
}

//=====================
// ROUTES
//=====================

// Showing home page
app.get("/", function (req, res) {
  res.render("home");
});

// Showing secret page
app.get("/secret", isLoggedIn, async function (req, res) {
  const fullName = require("fullname");
  const name = await fullName();

  if (req.user.roles === "admin") {
    res.render("secret_admin", { name });
  } else if (req.user.roles === "user") {
    res.render("secret", { name });
  }
});

// Showing register form
app.get("/register", function (req, res) {
  res.render("register");
});

// Handling user signup
app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username, roles: "user" },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        return res.render("register");
      }
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secret", { username: req.user.username });
      });
    }
  );
});

// Handling password change 1
app.post("/changepassword", isLoggedIn, function (req, res) {
  User.findOne({ username: req.user.username }, (err, user) => {
    if (err) {
      console.log(err);
      return res.render("account", { error: "Error, please try again" });
    }
    if (!user) {
      console.log("User not found");
      return res.render("account", { error: "Error, please try again" });
    }

    user.setPassword(req.body.newpassword, (err) => {
      if (err) {
        console.log(err);
        return res.render("account", { error: "Error, please try again" });
      }
      user.save((err) => {
        if (err) {
          console.log(err);
          return res.render("account", { error: "Error, please try again" });
        }
        req.logIn(user, (err) => {
          if (err) {
            console.log(err);
            return res.render("account", { error: "Error, please try again" });
          }
          //return res.render("account", { message: "Password changed successfully" });
          res.render("passwordChanged");
        });
      });
    });
  });
});

//Showing login form
app.get("/login", function (req, res) {
  res.render("login");
});

//Handling user login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secret",
    failureRedirect: "/login",
  }),
  function (req, res) {}
);

//Handling user logout
app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
});

//Handling account
app.get("/account", isLoggedIn, function (req, res) {
  res.render("account");
});

//Handling Admins
app.get("/secret_admin", isLoggedIn, isAdmin, function (req, res) {
  if (req.user.roles === "admin") {
    return res.render("secret_admin");
  } else {
    res.redirect("/secret_admin", { username: req.user.username });
  }
});

app.use(function (req, res, next) {
  res.locals.user = req.user;
  next();
});

//=====================
// CONNECTION
//=====================

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

var port = process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server Has Started!");
});

mongoose.set("strictQuery", false);
