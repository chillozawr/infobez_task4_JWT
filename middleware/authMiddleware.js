const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const {secret} = require('../config');

module.exports = function (req, res, next) {
	if (req.method === "OPTIONS") {
		next();
	}

	try {
		const cookies = cookie.parse(req.headers.cookie || '');
		const token = cookies.accessToken;
		if (!token) {
			return res.status(403).json({message: "Нет токена"});
		}
		const decodedData = jwt.verify(token, secret);
		req.user = decodedData;
		next();
	} catch (e) {
		console.log(e);
		return res.status(403).json({message: "Пользователь не авторизован"});
	}
};