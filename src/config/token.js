const jwt = require("jsonwebtoken");
const signToken = (id) => {
    return jwt.sign({ id: id }, process.env.JWT_SECRET,
        {expiresIn: process.env.JWT_EXPIRE,});
};
exports.createSendToken = async (user, res) => {
    try {
        const token = await signToken(user.email);
        const cookieOptions = {
            expires: new Date( new Date().getTime() + 360000),
            httpOnly: true,
        };
        res.cookie("jwt", token, cookieOptions);
    } catch (err) {
        console.log(err);
    }
};