var http = require('http');
var express = require("express");
var morgan = require('morgan');
var bp = require('body-parser');

var mongoose = require('mongoose');

var jwt = require('jsonwebtoken');

var log4js = require('log4js');

var config = require('./config');

var UserModel = require('./app/user/users');

var app = express();

app.use(morgan('dev'));
app.use(bp.json());
app.use(bp.urlencoded({
    extended: false
}));

log4js.configure(config.lgcf, {
    cwd: config.lgf
});

var logger = log4js.getLogger();

var server = http.createServer(app);
server.listen("8080", function() {
    logger.info("Server is running.");
    mongoose.connect(config.db);
    logger.info("Connected to database.");
});

function isAuthenticated(req, res, next) {
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    logger.debug("Got user token: ", token);

    if (!token) {
        res.status(403).json({
            error: 'Invalid user request or unauthorised request..!'
        });
        return;
    }

    var secretOrPrivateKey = config.jws;

    jwt.verify(token, secretOrPrivateKey, function(err, user) {
        if (err) {
            logger.error("Error in decoding token: ", err);
            res.status(403).json({
                error: 'Forbidden, Unauthorised request..!'
            });
            return;
        }

        logger.debug("Decoded payload: ", user);

        if (user) {
            UserModel.findOne({
                    username: user.username
                }, {
                    _id: 0,
                    __v: 0
                },
                function(err, user) {
                    if (err) {
                        logger.error("Error in finding user for authentication, error: ", err);
                        res.status(403).json({
                            error: 'Forbidden, Unauthorised request..!'
                        });
                        return;
                    }

                    if (!user) {
                        logger.error("User not found for authentication, error: ", err);
                        res.status(403).json({
                            error: 'Forbidden, Unauthorised request..!'
                        });
                        return;
                    }

                    req.user = user;
                    next();
                }); //end of finding user
        }
    }); //end of verify
}

app.get("/", function(req, res) {
    res.write("Welcome to JWT Auth Demo");
    res.end();
});

app.post("/register", function(req, res) {
    if (!req.body.username || !req.body.password) {
        res.json({
            error: "Please try with valid inputs..!"
        });
        return;
    }

    var newUser = new UserModel({
        username: req.body.username,
        password: req.body.password
    });

    newUser.save(function(err, user) {
        if (err) {
            logger.error("Failed registering new user, error: ", err);
            res.status(500).json({
                error: "Failed with internal errors..!"
            });
            return;
        }

        res.status(201).json(user);

    });
});

app.get("/users", isAuthenticated, function(req, res) {
    UserModel.find({}, {
        _id: 0,
        __v: 0
    }, function(err, colln) {
        if (err) {
            res.status(500).json({
                error: "Cowardly failing to get the requested data..!"
            });
            return;
        }

        res.json(colln);
    })
});

app.post("/signin", function(req, res) {
    if (!req.body.username || !req.body.password) {
        res.json({
            error: "Please try with valid credentials..!"
        });
        return;
    }

    UserModel.findOne({
            username: req.body.username
        }, {
            _id: 0,
            __v: 0
        },
        function(err, user) {

            if (err) {
                logger.error("Database error in finding user, error: ", err);
                res.status(500).json({
                    error: "Failed to process request, please try later..!"
                });
                return;
            }

            if (!user) {
                logger.error('User ', req.body.username, ' not found..!');
                res.status(403).json({
                    error: "Invalid credentials...!"
                });
                return;
            }

            if (user.password != req.body.password) {
                res.status(403).json({
                    error: "Invalid credentials...!"
                });
                return;
            }

            var payload = {
                username: user.username
            };
            var secretOrPrivateKey = config.jws;
            var options = {
                algorithm: "HS256",
                expiresIn: config.jwtem,
                issuer: user.username
            };

            //Asynch way of generating the token
            jwt.sign(payload, secretOrPrivateKey, options, function(err, jwtToken) {
                if (err) {
                    logger.error("Error in generating auth token, error: ", err);
                    res.status(500).json({
                        error: "Internal error in processing request, please retry later..!"
                    });
                }

                logger.debug("Token generated: ", jwtToken);

                res.json({
                    user: user,
                    'token': jwtToken
                });
            });

            return;
        }); //end of user find query
})

app.use(function(req, res) {
    res.status(404).json({
        error: "Requested resource not found..!"
    });
})