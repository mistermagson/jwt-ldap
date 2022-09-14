const User = require("../models/userModel");
const validatePassword = require("../config/bcrypt");
const hashPassword = require("../config/bcrypt");
const Token = require('../config/token');
const jwt = require("jsonwebtoken");


/////////////////////////////////////////////////////////////////
exports.userLogin = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const [user] = await User.find({ email: email });
        const validate = await validatePassword(password, user.password);
        if (validate) {
            await Token.createSendToken(user, res);
            res.status(200).json({
                status: "successfully",
                message: "user successfully logged in",
            });
        } else {
            res.status(401).json({
                status: "unauthorised",
                message: "email or password is invalid! ",
            });
        }
    } catch (err) {
        res.status(500).json({
            status: "error",
            message: "Something went wrong when logging in",
            data: {
                error: err,
            },
        });
    }
};
/////////////////////////////////////////////////////////////////
exports.protect = async (req, res, next) => {
    try {
        let token;
        if (req.cookies.jwt) {
            token = req.cookies.jwt;
        }
        if (!token) {
            return res.status(401).json({
                status: "unauthorised",
                message: "You are not logged in! Please log in to get access!",
            });
        }
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        const [currentUser] = await User.find({ email: decoded.id });
        if (!currentUser) {
            return res.status(401).json({
                status: "unauthorised",
                message: "The user belonging to this token does no longer exist!",
            });
        }
        req.user = currentUser;
        next();
    } catch (err) {
        return res.status(401).json({
            status: "unauthorised",
            message: "session has been expired! Please log in to get access!",
        });
    }
};

/////////////////////////////////////////////////////////////////
exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                status: "unauthorised",
                message: "You do not have permission to perform this action!",
            });
        }
        next();
    };
};

/////////////////////////////////////////////////////////////////
exports.getUser = async (req, res, next) => {
    try {
        const user = await User.find();
        user[0].password = undefined;
        res.status(200).json({
            status: "success",
            message: "All user are fetched!",
            data: {
                user,
            },
        });
    } catch (err) {
        console.log(err);
    }
};

/////////////////////////////////////////////////////////////////
exports.createUser = async (req, res, next) => {
    try {
        const hashed = await hashPassword(req.body.password);
        const Users = {
            full_name: req.body.full_name,
            email: req.body.email,
            role: req.body.role,
            password: hashed,
        };
        const user = await User.create(Users);
        res.status(201).json({
            status: "success",
            message: "user successfully created!",
            data: {
                user,
            },
        });
    } catch (err) {
        console.log(err);
        res.status(500).send({
            success: false,
            message: err.toString(),
        });
    }
};

/////////////////////////////////////////////////////////////////
exports.updateUser = async (req, res, next) => {
    try {
        const password = req.body.password;
        const passwordhash = await hashPassword(password);
        const user = await User.findOneAndUpdate(
            { email: req.user.email },
            { password: passwordhash },
            { new: true, runValidators: true }
        );
        res.status(200).json({
            status: "success",
            message: "user Password changing successfully",
            data: {
                user,
            },
        });
    } catch (err) {
        res.status(409).json({
            status: "failed",
            message: "user update failed!",
            data: {
                error: err,
            },
        });
    }
};
/////////////////////////////////////////////////////////////////
exports.deleteUser = async (req, res, next) => {
    try {
        const user = await User.findOneAndDelete(
            { email: req.params.email });
        res.status(200).json({
            status: "success",
            message: "user Password changing successfully",
            data: {
                user,
            },
        });
    } catch (err) {
        res.status(409).json({
            status: "failed",
            message: "user delete failed!",
            data: {
                error: err,
            },
        });
    }
};
/////////////////////////////////////////////////////////////////

exports.userLogout = (req, res, next) => {
    const cookieOptions = {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    };
    res.cookie("jwt", "user logged out", cookieOptions);
    res.status(200).json({
        status: "success",
        message: "Logged out",
    });
};