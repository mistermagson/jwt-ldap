const express = require('express');
const userController = require('../controllers/userController');
const router = express.Router();

router
    .route('/login')
    .post(userController.userLogin);
router
    .route("/user")
    .get(userController.protect,
        userController.restrictTo('admin'),
        userController.getUser)
    .post(userController.protect,
        userController.restrictTo('admin'),
        userController.createUser)
    .patch(userController.protect,
        userController.restrictTo('basic', 'admin'),
        userController.updateUser)
    .delete(userController.protect,
        userController.restrictTo('admin'),
        userController.deleteUser);
router
    .route('/logout')
    .get(userController.userLogout);

module.exports = router;