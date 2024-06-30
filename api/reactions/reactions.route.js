import express from 'express';
const reactionsRouter = express.Router();

reactionsRouter.get("/", (req, res) => { 
    res.send("reactions");
});


export default reactionsRouter;