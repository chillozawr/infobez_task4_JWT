const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const {secret, refresh} = require('../config');

module.exports = function (req, res, next) {
	if (req.method === "OPTIONS") {
		next();
	}

	try {
		const cookies = cookie.parse(req.headers.cookie || '');
		const accToken = cookies.refreshToken;
		// const recToken = cookies.accessToken;

		console.log(accToken);
		if (!accToken) {
			return res.status(403).json({message: "Пользователь не авторизован"});
		}
		const decodedData = jwt.verify(accToken, refresh);
		// const decodedData1 = jwt.verify(recToken, secret);
		req.user = decodedData;
		next();
	} catch (e) {
		console.log(e);
		return res.status(403).json({message: "Пользователь не авторизован"});
	}
};