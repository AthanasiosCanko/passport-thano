var express = require('express');
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var passport = require('passport');
var User = require('./user-model.js');

var app = new express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(passport.initialize());
app.use(express.static("public"));

app.get("/login", passport.authenticate("basic", {session: false}), function(req, res) {
    res.status(200).json({message: "Successful login!"});
});

var BasicStrategy = require('passport-http').BasicStrategy;

var strategy = new BasicStrategy(function(username, password, callback) {
	User.findOne({
		username: username
	}, function(err, user) {
		if (err) return callback(err);
		if (!user) return callback(null, false, {message: "Incorrect username."});
		
		user.validatePassword(password, function(err, isValid) {
			if (err) return callback(err);
			if (!isValid) return callback(null, false, {message: "Incorrect password."});
			return callback(null, user);
		});
	});
});

passport.use(strategy);

// POST request to sign up
app.post("/users", function(req, res) {
	
	// Body validation
	if (!req.body) {
		res.status(400).json({message: "No request body!"}); 
		return;
	}
	
	if (!('username' in req.body)) {
		res.status(422).json({message: "Missing field: username"}); 
		return;
	}
	
	var username = req.body.username;
	
	if (typeof username !== "string") {
		res.status(422).json({message: "Incorrect field type: username"}); 
		return;
	}
	
	username = username.trim();
	
	if (username === "") {
		res.status(422).json({message: "Incorrect field length: username"}); 
		return;
	}
	
	if (!('password' in req.body)) {
		res.status(422).json({message: "Missing field: password"}); 
		return;
	}	
	
	var password = req.body.password;
	
	if (typeof password !== "string") {
		res.status(422).json({message: "Incorrect field type: password"}); 
		return;
	}
	
	password = password.trim();
	
	if (password === "") {
		res.status(422).json({message: "Incorrect field length: username"}); 
		return;
	}
	
	// Generating salt, hashing and saving user
	bcrypt.genSalt(10, function(err, salt) {
		if (err) {
			res.status(500).json({message: "Internal Server Error!"});
			return;
		}
		
		bcrypt.hash(password, salt, function(err, hash) {
			if (err) {
				res.status(500).json({message: "Internal Server Error!"}); 
				return;
			}
			
			var user = new User({
				username: username,
				password: hash
			});
			
			// Getting a problem here...
			User.create(user, function(err, new_user) {
				if (err) {
					res.status(500).json({message: "Internal Server Error!"});
					return;
				}
				res.status(200).json(user);
			});
		});
	
	});
});

// Connecting to database and listening to environment port
mongoose.connect("mongodb://thano:thano@ds153765.mlab.com:53765/passport-thano").then(function() {
	app.listen(process.env.PORT || 7000);
});