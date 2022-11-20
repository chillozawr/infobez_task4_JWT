const User = require('./models/User');
const Role = require('./models/Role');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {validationResult} = require('express-validator');
const {secret, refresh} = require('./config');
const cookie = require('cookie');

const generateAccessToken = () => {
	let secretTime = new Date();
	let refreshTime = secretTime.setMinutes(secretTime.getSeconds() + 1);
	const payload = {
		refreshTime
	};
	const accessToken = jwt.sign(payload, secret, {expiresIn: "24h"});
	const refreshToken = jwt.sign(payload, refresh, {expiresIn: "24h"});
	return {accessToken, refreshToken};
};

// const generateAccessToken = (id, roles) => {
// 	const payload = {
// 		id,
// 		roles
// 	}
// 	const accessToken = jwt.sign(payload, secret, {expiresIn: "24h"});
// 	const refreshToken = jwt.sign(payload, refresh, {expiresIn: "24h"});
// 	return {accessToken, refreshToken};
// }

class authController {
	async registration(req, res) {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({message: "Ошибка при регистрации", errors});
			}
			const {username, password} = req.body;
			const candidate = await User.findOne({username});
			if (candidate) {
				res.status(400).json({message: 'Пользователь с таким именем уже существует'});
			}
			const hashPassword = bcrypt.hashSync(password, 7);
			const userRole = await Role.findOne({value: "USER"});
			const user = new User({username, password: hashPassword, roles: [userRole.value]});
			await user.save();
			return res.status(201).json({message: 'Пользователь успешно зарегистрирован'});
		} catch (e) {
			console.log(e);
			res.status(400).json({message: 'Registration error'});
		}
	};

	async login(req, res) {
		try {
			const {username, password} = req.body;
			const user = await User.findOne({username});
			if (!user) {
				return res.status(400).json({message: `Пользователь ${username} не найден`});
			}
			const validPassword = bcrypt.compareSync(password, user.password);
			if (!validPassword) {
				return res.status(400).json({message: `Введен неверный пароль`});
			}
			const {accessToken, refreshToken} = generateAccessToken();

			const accessSerialized = cookie.serialize('accessToken', accessToken, {
				httpOnly: true,
				// secure: process.env.NODE_ENV === 'production',
				sameSite: 'strict',
				maxAge: 60 * 60 * 24 * 30,
				// path: '/'
			});
			const refreshSerialized = cookie.serialize('refreshToken', refreshToken, {
				httpOnly: true,
				// secure: process.env.NODE_ENV === 'production',
				sameSite: 'strict',
				maxAge: 60 * 60 * 24 * 30,
				// path: '/'
			});

			const cookies = cookie.parse(req.headers.cookie || '');
			const accToken = cookies.accessToken;
			const refToken = cookies.refreshToken;
			res.setHeader('Set-Cookie', [accessSerialized, refreshSerialized]);
			return res.json({accToken, refToken, cookies});
		} catch (e) {
			console.log(e);
			res.status(400).json({message: 'Login error'});
		}
	};

	async getUsers(req, res) {
		try {
			const users = await User.find();
			res.send(users);
		} catch (e) {

		}
	};

	async refresh(req, res) {
		try {
			const {accessToken, refreshToken} = generateAccessToken();

			const accessSerialized = cookie.serialize('accessToken', String(accessToken), {
				httpOnly: true,
				secure: process.env.NODE_ENV === 'production',
				sameSite: 'strict',
				maxAge: 60 * 60 * 24 * 30,
				path: '/'
			});
			const refreshSerialized = cookie.serialize('refreshToken', String(refreshToken), {
				httpOnly: true,
				secure: process.env.NODE_ENV === 'production',
				sameSite: 'strict',
				maxAge: 60 * 60 * 24 * 30,
				path: '/'
			});
			res.setHeader('Set-Cookie', [accessSerialized, refreshSerialized]);

			return res.json({accessToken});
		} catch (e) {
			console.log(e);
			res.status(403).json({message: 'Forbidden'});
		}
	};
}

module.exports = new authController();