const express = require("express")
const bodyParser = require("body-parser")
const axios = require("axios").default
const { randomString, timeout } = require("./utils")
const url = require("url")

const config = {
	port: 9000,

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
	userInfoEndpoint: "http://localhost:9002/user-info",
}
let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/client")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", (req, res) => {
	state = randomString()
	const redirectUrl = url.parse(config.authorizationEndpoint)
	redirectUrl.query = {
		response_type: "code",
		client_id: config.clientId,
		redirect_uri: config.redirectUri,
		scope: "permission:name permission:date_of_birth",
		state,
	}
	res.redirect(url.format(redirectUrl))
})

app.get("/callback", async (req, res) => {
	if (req.query.state !== state) {
		res.status(403).end()
		return
	}

	const { code } = req.query

	try {
		let response = await axios({
			method: "POST",
			url: config.tokenEndpoint,
			auth: {
				username: config.clientId,
				password: config.clientSecret,
			},
			data: {
				code,
			},
			validateStatus: null,
		})
		const { access_token } = response.data

		response = await axios({
			method: "GET",
			url: config.userInfoEndpoint,
			headers: {
				authorization: `bearer ${access_token}`,
			},
		})

		res.render("welcome", { user: response.data })
	} catch (err) {
		console.error(err)
		res.status(500).end()
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = {
	app,
	server,
	getState() {
		return state
	},
	setState(s) {
		state = s
	},
}
