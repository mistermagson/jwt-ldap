const mongoose = require('mongoose');
const db = process.env.DB_URL;
mongoose.connect(db, { useNewUrlParser: true});
module.exports = mongoose;