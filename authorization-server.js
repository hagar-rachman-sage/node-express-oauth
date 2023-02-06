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
	res.render("login", { client, requestId, scope: client.scope })
})

app.post("/approve", (req, res) => {
	const { userName, password, requestId } = req.body
	const user = users[userName]
	if (!user) {
		res.status(401).end()
		return
	}
	if (!user.password === password) {
		res.status(401).end()
		return
	}
	const clientReq = requests[requestId]
	if (!clientReq) {
		res.status(401).end()
		return
	}

	delete requests[requestId]

	const authCode = randomString()
	authorizationCodes[authCode] = { clientReq, userName }

	const url = new URL(clientReq.redirect_uri)
	url.searchParams.append("code", authCode)
	url.searchParams.append("state", clientReq.state)

	res.redirect(url)
})

app.post("/token", (req, res) => {
	const { authorization } = req.headers
	if (!authorization) {
		res.status(401).end()
		return
	}

	const { clientId, clientSecret } = decodeAuthCredentials(authorization)
	const client = clients[clientId]
	if (!client || client.clientSecret !== clientSecret) {
		res.status(401).end()
		return
	}

	const { code } = req.body
	const obj = authorizationCodes[code]
	if (!obj) {
		res.status(401).end()
		return
	}
	delete authorizationCodes[code]
	const {
		userName,
		clientReq: { scope },
	} = obj
	const accessToken = jwt.sign({ userName, scope }, config.privateKey, {
		algorithm: "RS256",
		expiresIn: 300,
		issuer: "http://localhost:" + config.port,
	})

	res.json({ access_token: accessToken, token_type: "Bearer" })
})

const server = app.listen(config.port, "localhost", function () {
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
