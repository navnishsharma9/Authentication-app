const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const OAuth2Strategy = require("passport-oauth2");
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDb", (err) => {
  if (err) throw "Error Occured while connecting:" + err;
  else console.log("db is connected succesfully");
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  username: String,
  twitterId: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("user", userSchema);
passport.use(User.createStrategy());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://127.0.0.1:8000/auth/google/secrets",
    },
    (accessToken, refreshToken, profile, cb) => {
      User.findOrCreate(
        {
          username: profile.displayName,
          googleId: profile.id,
        },
        (err, user) => {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://127.0.0.1:3000/auth/facebook/secrets",
    },
    (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      User.findOrCreate(
        {
          username: profile.displayName,
          facebookId: profile.id,
        },
        (err, user) => {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new TwitterStrategy(
    {
      consumerKey: process.env.TWITTER_API_KEY,
      consumerSecret: process.env.TWITTER_API_SECRET,
      callbackURL: "http://127.0.0.1:3000/auth/twitter/secrets",
    },
    (token, tokenSecret, profile, done) => {
      console.log(profile);
      User.findOrCreate(
        {
          twitterId: profile.id,
        },
        (err, user) => {
          if (err) {
            return done(err);
          }
          done(null, user);
        }
      );
    }
  )
);

passport.use(
  new OAuth2Strategy(
    {
      authorizationURL:process.env.OAUTH_AUTH_DOMAIN_NAME,
      tokenURL:process.env.OAUTH_TOKEN_URL,
      clientID: process.env.OAUTH_CLIENT_ID,
      clientSecret: process.env.OAUTH_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/secrets",
    },
    (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      User.findOrCreate({ profileId: profile.email}, (err, user) => {
        return cb(err, user);
      });
    }
  )
);
app.route("/").get((req, res) => {
  res.render("home");
});

app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    const user = new User({
      email: req.body.username,
      password: req.body.password,
    });
    req.login(user, (err) => {
      if (err) {
        throw new Error("Error occured " + err);
      }
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    });
  });

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    User.register(
      {
        username: req.body.username,
      },
      req.body.password,
      (err) => {
        if (err) {
          res.redirect("/register");
          console.log("Error received :" + err);
        } else {
          passport.authenticate("local")(req, res, () => {
            res.render("secrets");
          });
        }
      }
    );
  });
app.get('/auth/login', passport.authenticate('oauth2', {scope:"openid email "}));

app.get('/auth/secrets',passport.authenticate('oauth2', {
  successRedirect:'/secrets',
  failureRedirect:'/login'
}));

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get('/login',(req, res)=>{
    res.render('login');
});
app.route("/logout").get((req, res) => {
  req.logout();
  res.redirect("/login");
});

app
  .route("/submit")
  .get((req, res) => {
    res.render("submit");
  })
  .post((req, res) => {
    const secretContent = req.body.secret;
    console.log(secretContent);
  });

app.route("/auth/google").get(
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.route("/auth/google/secrets").get(
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

app.route("/auth/facebook").get(
  passport.authenticate("facebook", {
    scope: ["email", "public_profile"],
  })
);

app.route("/auth/facebook/secrets").get(
  passport.authenticate("facebook", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.route("/auth/twitter").get(passport.authenticate("twitter"));

app.route("/auth/twitter/secrets").get(
  passport.authenticate("twitter", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);
app.listen(3000, () => {
  console.log("server listening on 3000");
});
