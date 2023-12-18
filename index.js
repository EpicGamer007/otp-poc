import express from "express";
const app = express();

import { generateSecret, verify } from "2fa-util";

import { Database } from "quick.replit";
const db = new Database();

import session from "cookie-session"

if(!process.env.SESSION_SECRET) {
	console.error("No SESSION_SECRET environment variable")
	process.exit(1);
}

app.use(session({
	name: "session",
	secret: process.env.SESSION_SECRET,
	maxAge: 1000 * 60 * 60 * 24 * 28,
}));

app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
	res.send(`
		<h1>Two-Factor Authentication</h1>
		<ol>
			<li>Go to <a href="/username">/username</a> and enter a random username</li>
			<li>Go to <a href="/generate">/generate</a> and get enter the generated code or scan the QR for the 2FA App of your choice (like Aegis)</li>
			<li>Go to <a href="/verify">/verify</a> and use enter the code you have. Depending on if it is correct, you will get a response!</li>
		</ol>
	`);
});

app.get("/username", (req, res) => {
	res.send(`
		<form method="POST" action="/username">
			<input name="username">
			<button type="submit">Submit</button>
		</form>
	`);
});

app.post("/username", (req, res) => {
	req.session.username = encodeURIComponent(req.body.username);
	res.send(`Set username to "${req.session.username}" Go to <a href="/generate">/generate</a> to generate 2fa auth now`)
});

app.get("/generate", async (req, res) => {
	if(!req.session.username) return res.redirect("/username");
	let secret = {};
	try {
		secret = await generateSecret(req.session.username, `${process.env.REPL_SLUG}-${process.env.REPL_OWNER}-repl-co`);
		await db.set(req.session.username, secret.secret);
	} catch(err) {
		return res.send(`Error: ${err}`);
	}
	res.send(`
		<img src="${secret.qrcode}" alt="QR Code for 2fa"/>
		<p>The Secret: ${secret.secret}</p>
		<p>Go to <a href="/verify">/verify</a> after entering the details to test it!</p>
	`);
});

app.get("/verify", async (req, res) => {
	if(!req.session.username) return res.redirect("/username");
	let secret = undefined;
	try {
		secret = await db.get(req.session.username);
		if(!secret) throw new Error(`No secret code in db, please generate the secret at <a href="/generate">/generate</a>.`);
	} catch (err) {
		return res.send(`${err}`);		
	}
	res.send(`
		<form method="POST" action="/verify">
			<input name="token">
			<button type="submit">Submit</button>
		</form>
	`);
});

app.post("/verify", async (req, res) => {
	if(!req.session.username) return res.redirect("/username");
	if(!req.body.token) return res.send(`No token submitted. <a href="/verify">Try again</a>`);
	let secret = undefined;
	try {
		secret = await db.get(req.session.username);
		if(!secret) throw new Error(`No secret code in db, please generate the secret at <a href="/generate">/generate</a>.`);
	} catch (err) {
		return res.send(`Error: ${err}`);		
	}
	let result = false;
	try {
		result = await verify(req.body.token, secret);
	} catch(err) {
		return res.send(`Error: ${err}`);
	}
	if(result) return res.send("Yay! You Authed :)");
	return res.send(`Fail :(. <a href="/verify">Try again</a>`);
});

app.listen(5050);