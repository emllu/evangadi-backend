import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config();

const port = process.env.DB_PORT; // Default MySQL port
const host = process.env.DB_HOST;
const database = process.env.DB_NAME;
const user = process.env.DB_USER;
const password =process.env.DB_PASSWORD;

console.log(`Connecting to the database on port: ${port}`);

export const connection = mysql.createConnection({
	host,
	port,
	database,
	user,
	password,
	// socketPath: "/Applications/MAMP/tmp/mysql/mysql.sock",
});

connection.connect((error) => {
	if (error) console.log(error);
	console.log("Connected to the database as ID: " + connection.threadId);
});
