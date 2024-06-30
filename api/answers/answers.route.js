import express from 'express';
import answersController from './answers.controller.js';
const answersRouter = express.Router();

answersRouter.get("/", (req, res) => { 
    res.send("answers");
});
answersRouter.get("/:id", answersController.getAnswersById);
answersRouter.post("/newanswer", answersController.newAnswers);

export default answersRouter;