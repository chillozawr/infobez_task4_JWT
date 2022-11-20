const {Schema, model} = require('mongoose');

const Role = new Schema({
	value: {type: String, unicode: true, default: 'USER'}
});

module.exports = model('Role', Role);