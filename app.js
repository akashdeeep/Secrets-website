require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const encrypt = require("mongoose-encryption");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const port = 3000;
const _ = require("lodash");
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
	session({
		secret: "Our little secret.",
		resave: false,
		saveUninitialized: false,
	})
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {
// 	secret: process.env.SECRET,
// 	encryptedFields: ["password"],
// });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
	done(null, user.id);
});
passport.deserializeUser((id, done) => {
	try {
		User.findById(id).then((user) => {
			done(null, user);
		});
	} catch (err) {
		console.log(err, "deserialize error");
	}
});

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL: "http://localhost:3000/auth/google/secrets",
			passReqToCallback: true,
		},
		function (request, accessToken, refreshToken, profile, done) {
			console.log(profile);
			User.findOrCreate({ googleId: profile.id }, function (err, user) {
				return done(err, user);
			});
		}
	)
);

app.get("/", (req, res) => {
	res.render("home");
});

app
	.route("/login")
	.get((req, res) => {
		res.render("login");
	})
	.post((req, res) => {
		const user = new User({
			username: req.body.username,
			password: req.body.password,
		});
		req.login(user, (err) => {
			if (err) {
				console.log(err, "login error");
			} else {
				passport.authenticate("local")(req, res, () => {
					res.redirect("/secrets");
				});
			}
		});
	});

app
	.route("/register")
	.get((req, res) => {
		res.render("register");
	})
	.post((req, res) => {
		User.register(
			{ username: req.body.username },
			req.body.password,
			(err, user) => {
				if (err) {
					console.log(err, "register error");
					res.redirect("/register");
				} else {
					passport.authenticate("local")(req, res, () => {
						res.redirect("/secrets");
					});
				}
			}
		);
	});

app.route("/secrets").get((req, res) => {
	try {
		User.find({ secret: { $ne: null } }).then((foundUsers) => {
			if (foundUsers) {
				res.render("secrets", { usersWithSecrets: foundUsers });
			}
		});
	} catch (err) {
		console.log(err, "secrets error");
	}
});

app.route("/logout").get((req, res) => {
	req.logout((err) => {
		if (err) {
			console.log(err, "logout error");
		} else {
			res.redirect("/");
		}
	});
});

app
	.route("/auth/google")
	.get(passport.authenticate("google", { scope: ["profile"] }), (req, res) => {
		// The request will be redirected to Google for authentication, so this
		// function will not be called.
	});

app.get(
	"/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	(req, res) => {
		// Successful authentication, redirect to secrets.
		res.redirect("/secrets");
	}
);

app
	.route("/submit")
	.get((req, res) => {
		if (req.isAuthenticated()) {
			res.render("submit");
		} else {
			res.redirect("/login");
		}
	})
	.post((req, res) => {
		const submittedSecret = req.body.secret;
		try {
			User.findById(req.user.id).then((foundUser) => {
				if (foundUser) {
					foundUser.secret = submittedSecret;
					try {
						foundUser.save().then(() => {
							res.redirect("/secrets");
						});
					} catch (err) {
						console.log(err, "save error");
					}
				}
			});
		} catch (err) {
			console.log(err, "submit error");
		}
	});

app.listen(port, () => {
	console.log(`Example app listening at http://localhost:${port}`);
});
