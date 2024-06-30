import express from "express";
import questionController from "./questions.controller.js";
const questionsRouter = express.Router();

questionsRouter.post("/createQuestion", questionController.createQuestion);
questionsRouter.get("/", questionController.getQuestions);
questionsRouter.get("/:id", questionController.getQuestionById);
export default questionsRouter;
