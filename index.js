require("./utils.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; // 1 hour in milliseconds

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.username) {
        var newUser = `
            <a href='/signup'><button>Sign up</button></a><br>
            <a href='/login'><button>Log in</button></a>
        `;
        res.send(newUser);
      
    } else {
        var validUser = `
            Hello, ${req.session.username}!<br>
            <a href='/members'><button>Go to Members Area</button></a><br>
            <a href='/logout'><button>Logout</button></a>
        `;
        res.send(validUser);
    }
});

app.get('/signup', (req, res) => {
    var signUpForm = `
        Create User
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='Name'><br>
            <input name='email' type='email' placeholder='Email'><br>
            <input name='password' type='password' placeholder='Password'><br>
            <button>Submit</button>
        </form>
    `;

    res.send(signUpForm);
});

app.post('/signupSubmit', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({name, email, password}, {abortEarly: false});

    if (validationResult.error != null) {
        var errorMessage = '';

        console.log(validationResult.error);

        validationResult.error.details.forEach(err => {
            if (err.message.includes('name')) {
                errorMessage += 'Name is required.<br>';
            };

            if (err.message.includes('email')) {
                errorMessage += 'Email is required.<br>';
            };

            if (err.message.includes('password')) {
                errorMessage += 'Password is required.<br>';
            };
        });

        var retrySignUp = `
            ${errorMessage}
            <a href="/signup">Try again</a>
        `;

        res.send(retrySignUp);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });

    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var loginForm = `
        Log In
        <form action='/loginSubmit' method='post'>
            <input name='email' type='email' placeholder='Email'><br>
            <input name='password' type='password' placeholder='Password'><br>
            <button>Submit</button>
        </form>
    `;

    res.send(loginForm);
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var retryLogin = `
        Invalid email/password combination.<br>
        <a href="/login">Try again</a>.
    `;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });

	if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(retryLogin);
        return;
	}

	const result = await userCollection
        .find({email: email})
        .project({name: 1, email: 1, password: 1, _id: 1})
        .toArray();

	if (result.length != 1) {
        console.log("user not found");
		res.send(retryLogin);
        return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
	}
	else {
		console.log("incorrect password");
		res.send(retryLogin);
	}
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const randomNumber = Math.floor(Math.random() * 3) + 1;
    var cat;

    switch (randomNumber) {
        case 1:
            cat = "<img src='/cat1.jpg' style='width:300px;'><br>";
            break;
        case 2:
            cat = "<img src='/cat2.jpg' style='width:300px;'><br>";
            break;
        case 3:
            cat = "<img src='/cat3.jpg' style='width:300px;'><br>";
            break;
    }

    const html = `
        <h1>Hello, ${req.session.username}!</h1>
        ${cat}
        <a href="/logout"><button>Sign out</button></a>
    `;

    res.send(html);
});


app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.use(function (req, res) {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 