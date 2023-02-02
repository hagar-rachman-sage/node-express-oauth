const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get("/authorize", (req, res) => {
	const { client_id: clientId, scope } = req.query
	const client = clients[clientId]

	if (!client) {
		res.status(401).end()
		return
	}

	const scopes = scope.split(" ")
	const isValidScopes = containsAll(client.scopes, scopes)
	if (!isValidScopes) {
		res.status(401).end()
		return
	}

	const requestId = randomString()
	requests[requestId] = req.query
	res.end()
})

const server = app.listen(config.port, "localhost", function () {
	console.log(`app listening on port ${config.port}`)
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = {
	app,
	requests,
	authorizationCodes,
	server,
}
