let secretTime = new Date();
let refreshTime = secretTime.setMinutes(secretTime.getMinutes() + 5);

// module.exports = {
// 	secret: secretTime.toString(),
// 	refresh: refreshTime.toString()
// };
module.exports = {
	secret: "SECRET_KEY_1",
	refresh: "SECRET_KEY_2"
};