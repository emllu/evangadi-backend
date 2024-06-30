import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();
import {connection} from './config/db.js'
import './config/install.js'
//import { upload} from './config/multer.js'

// routing 
import usersRouter from "./api/users/users.route.js"
import answersRouter from "./api/answers/answers.route.js";
import questionsRouter from "./api/questions/questions.route.js";
import replaysRouter from "./api/replays/replays.route.js";
import reactionsRouter from "./api/reactions/reactions.route.js";

// config .env

const port = process.env.SERVER_PORT;
const host = process.env.SERVER_HOST;



const server = express();

//middleware
server.use(cors({
    origin: (origin, callback) => {
        // Allow requests from any origin
        callback(null, true);
    },
    credentials: true // Allow credentials (cookies) to be sent
}));


server.use(express.urlencoded({ extended: true }));
server.use(express.json());

//routes
server.use("/api/users", usersRouter);
server.use("/api/answers", answersRouter);
server.use("/api/questions", questionsRouter);
server.use("/api/replays", replaysRouter);
server.use("/api/reactions", reactionsRouter);

server.get('/', (req, res) => { 
    res.send(`<h1>working ... </h1>`);
});




server.listen(port, (error) => { 
    if (error) console.log(error);
    console.log(`http://${host}:${[port]}`);
});
