const Router = require('express');
const router = new Router();
const controller = require('./authController');
const {check} = require('express-validator');
const authMiddleWare = require('./middleware/authMiddleware');
const roleMiddleWare = require('./middleware/roleMiddleware');
const refreshMiddleware = require('./middleware/refreshMiddleware');

router.post('/registration', [
	check('username', "Имя пользователя не может быть пустым").notEmpty(),
	check('password', "Пароль должен быть больше 4 и меньше 10 символов").isLength({min: 4, max: 10})
], controller.registration);
router.post('/login', controller.login);
router.post('/refresh', refreshMiddleware, controller.refresh );
router.get('/users', authMiddleWare, controller.getUsers);

module.exports = router;