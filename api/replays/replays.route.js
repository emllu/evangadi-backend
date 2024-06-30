import express from 'express';
const replayRouter = express.Router();

replayRouter.get("/", (req, res) => { 
    res.send("replay");
});


export default replayRouter;