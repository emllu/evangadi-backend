import express from 'express';
import auth from '../../auth/auth.js';

import userController from './users.controller.js';
//import { upload } from '../../config/multer.js';
const usersRouter = express.Router();

usersRouter.get("/", auth, userController.getUserById);
usersRouter.post('/createuser', userController.createUser)
usersRouter.post('/login', userController.login)
usersRouter.post('/userinfo',auth, userController.getUserById)
usersRouter.post('/profilepicture', userController.profilepicture)
usersRouter.post('/forgetpassword',userController.forgetPassword)
usersRouter.post('/confimCode', userController.confimCode)
usersRouter.post('/changePassword',userController.changePassword)


export default usersRouter;